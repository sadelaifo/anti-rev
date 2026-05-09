#!/usr/bin/env python3
"""expr_compiler — compile a math-expression string into an optimised callable.

Use case: long polynomial / engineering formulas (hundreds of terms,
named variables, scalar inputs) that need to be evaluated millions of
times.  Pure ``eval()`` is ~100us/call; this module gets to ~10-50ns/call.

Pipeline (top → bottom, fast → faster):

    expr string
        │
        │  sympy.sympify
        ▼
    sympy expression tree
        │
        │  sympy.cse — extract common subexpressions
        ▼
    list of (tmp = ...) + final expr
        │
        │  generate Python source, exec
        ▼
    real Python function (LOAD_FAST locals, ~500ns/call)
        │
        │  numba.njit(fastmath=True, cache=True)
        ▼
    JIT-compiled machine code (~10-50ns/call)

CSE is a meaningful win for expressions where the same subterm
(e.g. ``x*y``, ``x**2``) appears in many places.  numba is a meaningful
win for high-frequency calls; if you're calling once per batch on
numpy arrays, prefer ``numexpr.evaluate`` instead — different
optimisation regime.

──────────────────────────────────────────────────────────────────────
                            API reference
──────────────────────────────────────────────────────────────────────

There are five public entry points, picked by how the formula reaches
you:

    in-memory string ──────────────► make_expr_func
                                     make_expr_func_cached  (LRU)

    one formula in a JSON file ────► make_expr_func_from_json

    several formulas in a flat
    or detailed JSON file ─────────► make_funcs_from_json

    formulas scattered through
    a heterogeneous JSON tree ─────► load_expressions_from_json
                                     compile_expressions_in_data


1. make_expr_func(expr_str, params, *, jit=True, fastmath=True,
                  cache=True, debug=False)
   ----------------------------------------------------------------
   The core compiler.  Pass an expression and the positional
   parameter list:

       from expr_compiler import make_expr_func

       f = make_expr_func("a*b + c**2", ["a", "b", "c"])
       f(1.0, 2.0, 3.0)             # → 11.0

   ``params=[]`` is allowed for a fully constant expression.
   ``debug=True`` prints the generated Python source — useful when
   inspecting CSE output or precision of constants.

   Operators understood (anything Python's ``eval`` accepts on the
   same string): ``+ - * / ** ()``, unary minus, scientific notation
   (``1.5e-3``, ``-.5e12``), identifiers with digits / underscores
   (``var1``, ``x_long_name``).  ``**`` is right-associative
   (``2**3**2 == 512``) and binds tighter than ``*``.


2. make_expr_func_cached(expr_str, params_tuple, *, jit, fastmath, cache)
   ----------------------------------------------------------------
   ``functools.lru_cache``-wrapped variant — re-compiling the same
   ``(expr_str, params)`` pair returns the cached function instead
   of paying sympify+cse+exec+numba again.  Note ``params`` must be a
   *tuple* (hashable):

       f = make_expr_func_cached("a*b", ("a", "b"))


3. make_expr_func_from_json(json_path, expr_at, *,
                            constants_at=None, subexprs_at=None,
                            params_at=None, **compile_opts)
   ----------------------------------------------------------------
   Read one formula from a JSON config and compile it.  All path
   arguments accept either a tuple of segments
   (``("device", "transfer", "formula")``) or a dotted-with-bracket
   string (``"device.transfer.formula"``, ``"schedule[0].value"``).

   - ``expr_at`` (required): path to the formula string.
   - ``constants_at``: path to a ``{name: number}`` dict.  Each entry
     is *baked in* as a numeric literal at compile time, so it never
     appears as a function argument.  JSON floats are loaded with
     ``parse_float=str`` and forwarded to ``sp.Float`` as strings,
     so a 12-digit value like ``0.833333333333`` survives verbatim
     into the generated source (no rounding to default 15-dps).
   - ``subexprs_at``: path to a ``{name: expr_string}`` dict.  Each
     named sub-expression is inlined into the main formula via sympy
     AST substitution; entries may reference each other or any
     constant; cycles raise ``ValueError``.  Naming is purely an
     input-side readability feature — sympy's CSE rediscovers any
     common subterm so there's no runtime cost.
   - ``params_at``: optional override for parameter order.  Pass a
     single path or a list of paths, each pointing to a list of
     strings; values are concatenated into the positional-argument
     order.  Default (``None``) auto-detects the surviving free
     symbols and sorts them alphabetically.

   JSON shape this function expects::

       {
         "constants": {"k1": 6.5e-5, "k2": 0.001, "scale": 0.5},
         "subexprs":  {"power": "v*i", "loss":  "k1*v**2 + k2*i**2"},
         "formula":   "scale*power - loss"
       }

   Compile and call::

       from expr_compiler import make_expr_func_from_json

       f = make_expr_func_from_json(
           "config.json",
           expr_at      = "formula",
           constants_at = "constants",
           subexprs_at  = "subexprs",
       )
       f(1.5, 220.0)                # auto-detected order: i, v


4. make_funcs_from_json(json_path, **compile_opts) -> {name: callable}
   ----------------------------------------------------------------
   Top-level JSON object whose keys *are* the formula names.  Two
   per-entry shapes are supported and may be mixed::

       {
         "torque":  "0.5 * m * r**2 * omega",            # flat
         "voltage": {                                     # detailed
            "expr":   "I * R + L * dI_dt",
            "params": ["I", "R", "L", "dI_dt"]
         }
       }

   Use the detailed form when you need a non-alphabetical positional
   order, or when a variable name collides with a sympy constant
   (``E``, ``I``, ``pi``) and auto-detection would miss it.


5. load_expressions_from_json(json_path, is_expr, **compile_opts)
   compile_expressions_in_data(data, is_expr, **compile_opts)
   ----------------------------------------------------------------
   For files where formulas are *embedded* in an otherwise
   heterogeneous tree.  The walker recurses through dicts and lists,
   asks ``is_expr(path, value)`` at every leaf, and replaces only the
   matched ones with compiled callables — everything else passes
   through unchanged.

   Common predicate shapes::

       # Any string under a key named "formula" / "expr":
       lambda p, v: isinstance(v, str) and p and p[-1] in ("formula", "expr")

       # Specific path only:
       lambda p, v: p == ("device", "transfer_func")

       # Sentinel-prefix convention:
       lambda p, v: isinstance(v, str) and v.startswith("=")


Helper utilities
----------------

- ``get_at_path(data, path)`` — same path syntax as the loaders;
  raises ``KeyError`` / ``IndexError`` / ``TypeError`` with the
  failing segment named.  Useful for pulling unrelated fields out of
  the same JSON file.

This module is unrelated to antirev's runtime; it lives under tools/
because that's where the project keeps general-purpose helpers.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import tempfile
from pathlib import Path

import sympy as sp


def make_expr_func(expr_str: str, params: list[str], *,
                   jit: bool = True, fastmath: bool = True,
                   cache: bool = True, debug: bool = False):
    """Compile ``expr_str`` into a callable f(p1, p2, ...).

    Parameters
    ----------
    expr_str  : Python math expression, e.g. ``"-.5e-12*x**7*y**2*z + .18188888*x"``.
    params    : variable names occurring in expr_str, in the order they should
                become positional parameters of the returned function.
    jit       : if True (default), compile to machine code via numba.njit.
                Set False to fall back to a pure-Python exec'd function (no
                numba dependency, ~10x slower than JIT).
    fastmath  : numba fastmath knob.  Lets LLVM reorder ops, use FMA, etc.
                Significant win on long polynomials but assumes no NaN/Inf
                inputs.  Disable if your domain admits NaN.
    cache     : numba caches the compiled binary on disk so subsequent
                process starts skip the JIT compile.
    debug     : print the generated Python source — useful when checking
                what CSE produced.

    Returns
    -------
    callable f(p1, p2, ...) -> float
    """
    # Long expressions (thousands of `+` / `*` terms) overflow two
    # different stacks during compile:
    #
    #   1. Python's recursionlimit  (default 1000) — sympy's tree
    #      walks (sympify, cse, pycode) and CPython's own AST build
    #      inside our exec() recurse once per operator.
    #
    #   2. The OS thread stack       (Windows main thread is 1 MB,
    #      Linux ~8 MB) — this caps how deep recursion can go *even
    #      with recursionlimit raised*.  Hitting the C-stack limit
    #      shows up as the same RecursionError, so it's easy to
    #      misdiagnose.
    #
    # Solution: run the whole compile pipeline in a worker thread
    # with a large stack and an elevated Python recursionlimit.  The
    # numba JIT decoration happens after, in the caller's thread, so
    # JIT-time state (caches, dispatcher registries) lives where the
    # user expects.
    fn = _run_in_big_stack(
        lambda: _compile_pyfunc(expr_str, params, debug=debug),
        stack_mb=256,
    )

    if jit:
        from numba import njit
        fn = njit(cache=cache, fastmath=fastmath)(fn)

    return fn


def _compile_pyfunc(expr_str: str, params: list[str], *, debug: bool):
    """Compile a Python function from `expr_str` with no
    constant/subexpr substitutions.  Thin wrapper around
    :func:`_compile_with_subst` for the case where substitutions have
    already been applied or aren't needed (the make_expr_func entry
    point)."""
    return _compile_with_subst(expr_str, params, None, None, debug=debug)


def _compile_with_subst(formula: str, params_explicit, constants, subexprs,
                        *, debug: bool):
    """Single-pass compile with content-addressed caching.

    Cache key: SHA-1 of (formula + params_explicit + constants +
    subexprs).  If a cache file with that key already exists on disk
    under <tempdir>/expr_compiler_gen/, skip the entire sympy
    pipeline and just exec the previously-generated source.

    Cache miss: do the work in one pass — sympify the formula once,
    apply both subexpr and constant substitutions in a single
    xreplace, auto-detect parameters (or use the supplied list),
    run CSE, generate source with chunked main, write to the cache
    file, exec.

    Why this is worth doing:

      - Re-running the same JSON config skips ~15 seconds per
        large formula (sympify is the dominant cost).
      - Editing one formula in a file with hundreds of others only
        recompiles the changed one; the rest cache-hit.
      - The single-pass substitution avoids two str()→sympify round
        trips that were happening across the
        _expand_subexprs / _substitute_constants / _compile_pyfunc
        chain — first-run compile is also ~3x faster.

    Returns a plain Python function; JIT decoration happens in the
    caller's process so numba's dispatcher state lives where the
    user expects.
    """
    cache_key = _compute_compile_key(
        formula, params_explicit, constants, subexprs,
    )
    src_file = _cache_path_for_key(cache_key)

    if os.path.exists(src_file):
        with open(src_file, 'r', encoding='utf-8') as f:
            src = f.read()
        if debug:
            print(f"--- cache hit: {src_file} ---")
            print(src)
    else:
        src = _generate_source_with_subst(
            formula, params_explicit, constants, subexprs, debug,
        )
        tmp = src_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(src)
        os.replace(tmp, src_file)

    code = compile(src, src_file, 'exec')
    ns: dict = {'__file__': src_file}
    exec(code, ns)
    return ns['_expr']


def _generate_source_with_subst(formula, params_explicit, constants,
                                subexprs, debug):
    """Single sympify pass: parse formula, apply subexpr + constant
    substitutions at AST level (one xreplace, no string round
    trips), run CSE, emit chunked Python source.  Returns the source
    string.  Recursion-heavy — call from inside the big-stack
    worker thread."""
    expr = _sympify_chunked(formula)

    # Build a unified xreplace dict: subexprs + constants, then
    # resolve to a fixed point so each subexpr's value already has
    # all referenced constants and other subexprs baked in.
    #
    # Why fixed-point: sympy's xreplace is a single-pass tree walk —
    # when it replaces ``loss`` with ``k1*v**2 + k2*i**2``, the
    # newly-substituted ``k1``/``k2`` are NOT re-visited.  If we
    # didn't pre-resolve, those would survive as free symbols in
    # the output even though the user gave numeric values for them.
    sub_dict: dict = {}
    if subexprs:
        sub_dict.update({sp.Symbol(name): sp.sympify(s)
                         for name, s in subexprs.items()})
    if constants:
        sub_dict.update({sp.Symbol(name): _to_sympy_constant(name, value)
                         for name, value in constants.items()})

    if sub_dict:
        # Resolve to a fixed point.  Each iteration walks every
        # entry's value and applies the current sub_dict once;
        # numeric constants are no-ops, but subexpr values reduce
        # toward fully-substituted form.
        for _ in range(len(sub_dict) + 1):
            changed = False
            for sym, e in list(sub_dict.items()):
                new = e.xreplace(sub_dict)
                if new != e:
                    sub_dict[sym] = new
                    changed = True
            if not changed:
                break
        # Cycle check — any value still referencing a sub_dict key
        # after convergence is a circular reference (e.g. subexprs
        # ``a -> b, b -> a`` settle at ``a -> a, b -> a``).
        names = set(sub_dict)
        for sym, e in sub_dict.items():
            leftover = e.free_symbols & names
            if leftover:
                raise ValueError(
                    f"substitution cycle: {sym} still depends on "
                    f"{sorted(str(s) for s in leftover)} after resolution")

        expr = expr.xreplace(sub_dict)

    # Determine parameter list.
    if params_explicit is not None:
        params = list(params_explicit)
    else:
        params = sorted(str(s) for s in expr.free_symbols)

    # CSE — drop 'basic' optimizations for very wide Adds (O(N²) and
    # finds nothing on flat polynomials).
    opt_level = 'basic' if not (
        isinstance(expr, sp.Add) and len(expr.args) > 10_000
    ) else None
    sub_exprs, [main] = sp.cse(expr, optimizations=opt_level)

    lines = [f"def _expr({', '.join(params)}):"]
    for tmp, val in sub_exprs:
        lines.append(f"    {tmp} = {sp.pycode(val)}")
    chunk_lines, final_pycode = _emit_chunked_main(main)
    lines.extend(chunk_lines)
    lines.append(f"    return {final_pycode}")
    src = "\n".join(lines) + "\n"

    if debug:
        print("--- generated source ---")
        print(src)
        print(f"--- {len(sub_exprs)} CSE temps, "
              f"{len(chunk_lines)} chunk temps ---")
    return src


def _to_sympy_constant(name, value):
    """Bool / str / float / int → sp.Float | sp.Integer.  String form
    preserves the digit count exactly; floats preserve up to IEEE-754."""
    if isinstance(value, bool):
        raise TypeError(f"constant {name!r}: bool is not a numeric value")
    if isinstance(value, str):
        return sp.Float(value)
    if isinstance(value, float):
        return sp.Float(value)
    if isinstance(value, int):
        return sp.Integer(value)
    raise TypeError(f"constant {name!r} must be int / float / "
                    f"numeric-string, got {type(value).__name__}")


def _compute_compile_key(formula, params_explicit, constants, subexprs):
    """Stable SHA-1 hash of every input that affects the generated
    code.  Two compiles with identical (formula, params, constants,
    subexprs) produce the same key and reuse the same cache file —
    that's how the second run becomes near-instant.

    constants values are stringified before hashing because
    parse_float=str gives us strings whereas Python ints stay ints;
    the cache should hit regardless of which form the caller
    supplies for the same numeric value.
    """
    payload = {
        'formula': formula,
        'params':  list(params_explicit) if params_explicit else None,
        'constants': sorted(
            (k, str(v)) for k, v in constants.items()
        ) if constants else None,
        'subexprs': sorted(subexprs.items()) if subexprs else None,
    }
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha1(canonical.encode('utf-8')).hexdigest()[:16]


def cache_dir_path() -> str:
    """Path of the on-disk compile cache directory.

    All generated source files (and numba's ``.nbi`` / ``.nbc`` next
    to them in ``__pycache__/``) live here.  Useful for inspecting
    the cache manually::

        import os, expr_compiler
        for f in os.listdir(expr_compiler.cache_dir_path()):
            print(f)

    The directory is created lazily on first compile.
    """
    return os.path.join(tempfile.gettempdir(), 'expr_compiler_gen')


def _cache_path_for_key(key: str) -> str:
    """Disk path for cache key.  Persists for the lifetime of the
    system temp dir (typically across processes within the same OS
    session)."""
    cache_dir = cache_dir_path()
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f'_expr_{key}.py')


def clear_compile_cache(*, older_than_days: float | None = None) -> dict:
    """Remove cached generated source files (and the numba ``.nbi`` /
    ``.nbc`` next to them).  After this, the next compile pays the
    full sympy + LLVM cost again — useful when you've upgraded
    sympy / numba, suspect a corrupted cache, or just want a clean
    slate before benchmarking.

    Parameters
    ----------
    older_than_days : float, optional
        If given, only remove files older than this many days
        (by mtime).  Default ``None`` removes everything.  Useful for
        a periodic cleanup that doesn't disturb hot entries::

            clear_compile_cache(older_than_days=30)

    Returns
    -------
    dict with keys::

        {
          'removed_files': int,   # how many files were deleted
          'freed_bytes':   int,   # total bytes reclaimed
          'cache_dir':     str,   # path that was cleaned
        }

    Safe to call when the cache directory doesn't exist (returns
    ``removed_files=0``).  Concurrent compiles in another process
    that race against this call may either succeed (the file they
    wrote isn't deleted) or harmlessly recompile.
    """
    import shutil
    import time

    cache_dir = cache_dir_path()
    report = {'removed_files': 0, 'freed_bytes': 0, 'cache_dir': cache_dir}

    if not os.path.isdir(cache_dir):
        return report

    threshold = (time.time() - older_than_days * 86400.0
                 if older_than_days is not None else None)

    if threshold is None:
        # Wholesale wipe — count first, then rmtree.
        for root, _dirs, files in os.walk(cache_dir):
            for name in files:
                path = os.path.join(root, name)
                try:
                    report['freed_bytes'] += os.path.getsize(path)
                    report['removed_files'] += 1
                except OSError:
                    pass
        shutil.rmtree(cache_dir, ignore_errors=True)
        return report

    # Age-filtered: walk and unlink old files, then prune empty dirs.
    for root, _dirs, files in os.walk(cache_dir, topdown=False):
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.getmtime(path) > threshold:
                    continue
                size = os.path.getsize(path)
                os.unlink(path)
                report['removed_files'] += 1
                report['freed_bytes'] += size
            except OSError:
                pass
        # Best-effort: remove now-empty subdirs (e.g. __pycache__/).
        try:
            if not os.listdir(root) and root != cache_dir:
                os.rmdir(root)
        except OSError:
            pass
    return report


def reference_value(formula, sample, *, constants=None,
                    subexprs=None) -> float:
    """Compute ``formula(sample)`` using sympy's substitution engine —
    independent of the compile pipeline (no CSE, no pycode, no exec).
    Use it as a ground-truth reference when verifying a compiled
    function on a huge formula where Python's ``eval()`` blows the
    main-thread C-stack.

    Args:
        formula:   the original formula string from your JSON
        sample:    ``{var_name: number}`` — values for every free
                   variable in the formula
        constants: same dict shape passed to make_expr_func_from_json;
                   substituted into the formula before evaluation
        subexprs:  same dict shape passed to make_expr_func_from_json

    Returns:
        Python float — the formula's value at ``sample``.

    Slow.  Each call sympify-parses the full formula and runs
    ``evalf()`` on the resolved tree; expect several seconds on
    400 KB inputs.  Intended for verification, not hot paths.

    Note that the constants / subexprs dicts must match what was
    passed to the compiler, otherwise the reference will disagree
    with the compiled function for reasons that have nothing to do
    with bugs.  An easy way to keep them in sync is to load them
    from the same JSON the compiler used::

        with open("config.json") as fh:
            cfg = json.load(fh, parse_float=str)
        ref = reference_value(
            cfg["expr"]["f1"], {"v": 220.0, "i": 1.5},
            constants = cfg["constants"],
            subexprs  = cfg["subexprs"],
        )
    """
    return _run_in_big_stack(
        lambda: _reference_value_impl(formula, sample, constants, subexprs),
        stack_mb=256,
    )


def _reference_value_impl(formula, sample, constants, subexprs):
    import sys
    old = sys.getrecursionlimit()
    if old < 1_000_000:
        sys.setrecursionlimit(1_000_000)
    try:
        expr = _sympify_chunked(formula)

        # Build merged substitution dict (mirrors _generate_source_with_subst).
        sub_dict: dict = {}
        if subexprs:
            sub_dict.update({sp.Symbol(n): sp.sympify(s)
                             for n, s in subexprs.items()})
        if constants:
            sub_dict.update({sp.Symbol(n): _to_sympy_constant(n, v)
                             for n, v in constants.items()})
        if sub_dict:
            for _ in range(len(sub_dict) + 1):
                changed = False
                for sym, e in list(sub_dict.items()):
                    new = e.xreplace(sub_dict)
                    if new != e:
                        sub_dict[sym] = new
                        changed = True
                if not changed:
                    break
            expr = expr.xreplace(sub_dict)

        if sample:
            var_dict = {sp.Symbol(n): sp.Float(str(v))
                        for n, v in sample.items()}
            expr = expr.xreplace(var_dict)

        return float(expr.evalf())
    finally:
        sys.setrecursionlimit(old)


def verify(funcs, formulas, sample, *, constants=None, subexprs=None,
           eps: float = 1e-9, file=None):
    """Cross-check each compiled function against
    :func:`reference_value` at one sample point.

    Args:
        funcs:     either a single callable (paired with ``formulas``
                   as a string) or a dict ``{name: callable}`` (paired
                   with ``formulas`` as a dict ``{name: formula_str}``).
        formulas:  the formula text(s); shape must match ``funcs``.
        sample:    ``{var_name: number}`` — must contain values for
                   every parameter of every function being checked.
        constants, subexprs: as for :func:`make_expr_func_from_json`.
        eps:       relative-error tolerance for the OK / FAIL verdict.
        file:      where to print the report (default stdout).

    Prints a per-formula line with the reference value, the compiled
    value, and the relative error.  Returns a list of dicts so you
    can post-process programmatically::

        records = verify(funcs, formulas, sample, constants=...,
                          subexprs=...)
        worst = max(records, key=lambda r: r.get('rel_err') or 0)

    A typical output::

        Verifying 3 function(s) at sample {v=220.0, i=1.5}
          [OK  ] f_power: ref=165         got=165         rel_err=0.00e+00
          [OK  ] f_loss:  ref=3.14825     got=3.14825     rel_err=2.10e-16
          [FAIL] f_temp:  ref=72.5872     got=72.5870     rel_err=2.76e-06
        2/3 passed
    """
    import sys
    if file is None:
        file = sys.stdout

    # Normalise to dicts internally.
    if callable(funcs) and isinstance(formulas, str):
        funcs    = {"<fn>": funcs}
        formulas = {"<fn>": formulas}
    elif isinstance(funcs, dict) and isinstance(formulas, dict):
        pass
    else:
        raise TypeError(
            "funcs and formulas must be both single (callable + str) or "
            f"both dicts, got {type(funcs).__name__} and "
            f"{type(formulas).__name__}")

    sample_str = ", ".join(f"{k}={v}" for k, v in sample.items())
    print(f"Verifying {len(funcs)} function(s) at sample {{{sample_str}}}",
          file=file)

    records: list = []
    for name, fn in funcs.items():
        record = {'name': name, 'sample': dict(sample),
                  'ref': None, 'compiled': None, 'rel_err': None, 'ok': False}

        if name not in formulas:
            print(f"  [SKIP] {name}: no entry in `formulas`", file=file)
            record['error'] = 'missing formula'
            records.append(record)
            continue

        py_fn = getattr(fn, 'py_func', fn)
        n_args = py_fn.__code__.co_argcount
        args = list(py_fn.__code__.co_varnames[:n_args])
        missing = [a for a in args if a not in sample]
        if missing:
            print(f"  [SKIP] {name}: sample missing {missing}", file=file)
            record['error'] = f'sample missing {missing}'
            records.append(record)
            continue

        try:
            ref = reference_value(formulas[name], sample,
                                  constants=constants, subexprs=subexprs)
        except Exception as e:
            print(f"  [ERR ] {name}: reference failed: "
                  f"{type(e).__name__}: {e}", file=file)
            record['error'] = f'reference: {e}'
            records.append(record)
            continue

        try:
            got = fn(*[sample[a] for a in args])
        except Exception as e:
            print(f"  [ERR ] {name}: compiled call failed: "
                  f"{type(e).__name__}: {e}", file=file)
            record['ref'] = float(ref)
            record['error'] = f'compiled call: {e}'
            records.append(record)
            continue

        diff = abs(float(got) - float(ref))
        rel = diff / (abs(float(ref)) + 1e-300)
        ok = rel < eps
        status = 'OK  ' if ok else 'FAIL'
        print(f"  [{status}] {name}: ref={float(ref):.6g}  "
              f"got={float(got):.6g}  rel_err={rel:.2e}", file=file)

        record.update({'ref': float(ref), 'compiled': float(got),
                       'rel_err': rel, 'ok': ok})
        records.append(record)

    n_pass = sum(1 for r in records if r.get('ok'))
    print(f"{n_pass}/{len(records)} passed", file=file)
    return records


def describe(funcs, *, sample=None, file=None):
    """Pretty-print compiled function(s) — names, signatures, JIT
    status, source file paths, and optionally evaluate each at a
    sample point.

    Accepts either:
      - a single callable from ``make_expr_func`` /
        ``make_expr_func_from_json``
      - a dict from ``make_expr_funcs_from_json`` /
        ``make_funcs_from_json``

    ``sample`` is an optional ``{var_name: value}`` dict.  For each
    function whose parameters are all present in ``sample``, the
    sample values are passed in (in the function's own argument
    order) and the result is printed.  Functions with parameters
    not in ``sample`` get a "skipped: missing X" line so it's
    obvious nothing ran.

    Example::

        funcs = make_expr_funcs_from_json("config.json", ...)
        describe(funcs, sample={"v": 220.0, "i": 1.5, "t": 25.0})

    Output::

        3 compiled function(s):
          f1(i, v)        [JIT]  /tmp/expr_compiler_gen/_expr_8af9.py
                f(1.5, 220.0) = 173.85
          f2(t)           [JIT]  /tmp/expr_compiler_gen/_expr_3a7c.py
                f(25.0,) = 0.625
          f3(p, v)        [JIT]  /tmp/expr_compiler_gen/_expr_5b22.py
                skipped: sample missing ['p']

    ``file`` defaults to ``sys.stdout``; pass any file-like for
    custom routing.
    """
    import sys

    if file is None:
        file = sys.stdout

    # Normalise input into a list of (name, callable) tuples.
    if callable(funcs):
        items = [("<fn>", funcs)]
    elif isinstance(funcs, dict):
        items = list(funcs.items())
    else:
        raise TypeError(f"describe expected callable or dict, got "
                        f"{type(funcs).__name__}")

    if not items:
        print("(no compiled functions)", file=file)
        return

    # Build per-row info, then print with aligned columns.
    rows = []
    for name, fn in items:
        py_fn = getattr(fn, 'py_func', fn)
        n_args = py_fn.__code__.co_argcount
        args = list(py_fn.__code__.co_varnames[:n_args])
        is_jit = hasattr(fn, 'py_func')
        src = py_fn.__code__.co_filename
        if len(src) > 60:
            src = "..." + src[-57:]
        rows.append({
            'name': name, 'fn': fn, 'args': args,
            'is_jit': is_jit, 'src': src,
        })

    sig_width = max(len(f"{r['name']}({', '.join(r['args'])})") for r in rows)

    print(f"{len(rows)} compiled function(s):", file=file)
    for r in rows:
        sig = f"{r['name']}({', '.join(r['args'])})"
        kind = "[JIT]" if r['is_jit'] else "[py] "
        print(f"  {sig:<{sig_width}}  {kind}  {r['src']}", file=file)
        if sample is not None:
            missing = [a for a in r['args'] if a not in sample]
            if missing:
                print(f"        skipped: sample missing {missing}", file=file)
            else:
                vals = [sample[a] for a in r['args']]
                try:
                    result = r['fn'](*vals)
                    print(f"        f{tuple(vals)} = {result}", file=file)
                except Exception as e:
                    print(f"        error during call: "
                          f"{type(e).__name__}: {e}", file=file)


def _split_top_level_terms(s: str):
    """Walk ``s`` once and return ``[(sign, term_str), ...]`` where the
    splits are at *top-level* ``+`` / ``-`` operators (not inside
    parens or brackets, not part of scientific notation, and not
    unary signs leading another operator).

    Example::

        "0.5*v*i + 1.5e-3*x - (a + b)*c"
          → [('+', '0.5*v*i'),
             ('+', '1.5e-3*x'),
             ('-', '(a + b)*c')]

    Used as a string-level pre-pass before ``sp.sympify`` on huge
    formulas — sympy's parser recurses once per operator and a 400+ KB
    single expression overflows even a 256 MB stack.  Splitting first
    keeps each sympify call's input small.
    """
    pieces: list = []
    paren = 0
    bracket = 0
    n = len(s)

    i = 0
    while i < n and s[i].isspace():
        i += 1
    if i < n and s[i] in '+-':
        sign = s[i]
        i += 1
    else:
        sign = '+'
    start = i

    def is_term_continuation(idx: int) -> bool:
        """A ``+`` / ``-`` at idx belongs to the current term (i.e.
        unary or scientific-notation exponent) rather than separating
        a new term."""
        j = idx - 1
        while j >= start and s[j].isspace():
            j -= 1
        if j < start:
            return True                           # beginning of term
        prev = s[j]
        if prev in 'eE':
            k = j - 1
            while k >= start and s[k].isspace():
                k -= 1
            if k >= start and s[k].isdigit():
                return True                       # scientific exponent sign
        if prev in '+-*/%(,=<>!^~|&':
            return True                           # unary after operator
        return False

    while i < n:
        c = s[i]
        if c == '(':
            paren += 1
        elif c == ')':
            paren -= 1
        elif c == '[':
            bracket += 1
        elif c == ']':
            bracket -= 1
        elif paren == 0 and bracket == 0 and c in '+-':
            if not is_term_continuation(i):
                term = s[start:i].strip()
                if term:
                    pieces.append((sign, term))
                sign = c
                start = i + 1
        i += 1

    term = s[start:].strip()
    if term:
        pieces.append((sign, term))
    return pieces


def _sympify_chunked(expr_str: str, locals_dict: dict | None = None,
                    threshold: int = 20_000):
    """Drop-in for ``sp.sympify(expr_str, locals=locals_dict)`` that
    handles arbitrarily long inputs.  Below ``threshold`` bytes uses
    sympy's parser directly; above it, splits ``expr_str`` at top-
    level ``+`` / ``-`` and sympifies each piece independently before
    combining via ``sp.Add``.

    The combined tree is shaped ``Add(piece1, piece2, ..., piece_n)``
    — flat, depth ≈ max(piece depth), so downstream operations
    (``xreplace``, ``cse``, ``pycode``) traverse it iteratively over
    args without recursing N levels deep.

    Limitation: a long *product* at top level (no top-level + or -)
    can't be split this way; if you have an expression dominated by
    multiplication chains and it overflows, restructure the input or
    raise the OS thread stack.
    """
    if locals_dict is None:
        locals_dict = {}
    if len(expr_str) <= threshold:
        return sp.sympify(expr_str, locals=locals_dict)

    pieces = _split_top_level_terms(expr_str)
    if len(pieces) <= 1:
        # No top-level + or - to split on; fall back and hope the
        # stack is big enough.  Caller must already be inside a
        # big-stack thread.
        return sp.sympify(expr_str, locals=locals_dict)

    parsed: list = []
    for sign, term in pieces:
        e = sp.sympify(term, locals=locals_dict)
        if sign == '-':
            e = -e
        parsed.append(e)
    return sp.Add(*parsed) if parsed else sp.Integer(0)


def _emit_chunked_main(main, chunk_size: int = 100):
    """If ``main`` is a long Add, split it into chunks of
    ``chunk_size`` terms each, emit ``_s0 = ...``, ``_s1 = ...`` lines
    for each chunk, and return ``(lines, "_s0 + _s1 + ...")`` for the
    final return.  Otherwise return ``([], pycode(main))`` so the
    caller emits a single return.

    Why: CPython parses ``a+b+c+...+z`` into a left-deep BinOp tree
    and recurses once per operator during compilation.  A 5000-term
    return statement crashes even with a 200k recursionlimit on
    platforms where the C-stack runs out first.  Chunking limits each
    line's depth to ``chunk_size`` and the final reduction's depth to
    ``ceil(N/chunk_size)``.
    """
    if not isinstance(main, sp.Add) or len(main.args) <= chunk_size:
        return [], sp.pycode(main)

    args = main.args
    lines: list[str] = []
    chunk_names: list[str] = []
    for i in range(0, len(args), chunk_size):
        name = f"_s{len(chunk_names)}"
        chunk_names.append(name)
        chunk_expr = sp.Add(*args[i:i + chunk_size], evaluate=False)
        lines.append(f"    {name} = {sp.pycode(chunk_expr)}")
    return lines, " + ".join(chunk_names)


def _run_in_big_stack(target, *, stack_mb: int = 256):
    """Run ``target()`` in a thread with ``stack_mb`` megabytes of
    stack space.  Returns target's value or re-raises its exception.

    Use case: deeply recursive sympy / CPython compile of multi-
    thousand-term expressions can blow the OS thread stack
    (Windows main thread is only 1 MB).  ``threading.stack_size``
    sets the size process-wide for new threads; we save and restore
    so the main thread's setting isn't disturbed.

    The platform-allowed maximum stack size differs by OS and Python
    build (Windows often caps below 256 MB).  We try the requested
    size first, then halve and retry on ``ValueError`` until we land
    on something the OS accepts — anything ≥ 8 MB is enough for
    every test we have.  If even 8 MB is rejected, fall back to the
    process default (which is what the user already had before this
    function existed, so no regression).
    """
    import threading
    box = {'result': None, 'error': None}

    def runner():
        try:
            box['result'] = target()
        except BaseException as e:    # noqa: BLE001 — re-raised below
            box['error'] = e

    saved = threading.stack_size()
    candidate_mb = stack_mb
    set_ok = False
    while candidate_mb >= 8:
        try:
            threading.stack_size(candidate_mb * 1024 * 1024)
            set_ok = True
            break
        except (ValueError, OSError):
            candidate_mb //= 2
    try:
        t = threading.Thread(target=runner)
        t.start()
        t.join()
    finally:
        if set_ok:
            threading.stack_size(saved)

    if box['error'] is not None:
        raise box['error']
    return box['result']


@functools.lru_cache(maxsize=128)
def make_expr_func_cached(expr_str: str, params: tuple[str, ...], *,
                          jit: bool = True, fastmath: bool = True,
                          cache: bool = True):
    """LRU-cached wrapper.  Re-compiling the same (expr_str, params) pair
    returns the same compiled function instead of paying the
    sympify+cse+exec+numba cost again.

    ``params`` must be a tuple (hashable).
    """
    return make_expr_func(expr_str, list(params),
                          jit=jit, fastmath=fastmath, cache=cache)


# ---------------------------------------------------------------------
# JSON loader — compile a whole file of formulas in one call.
# ---------------------------------------------------------------------
def _detect_params(expr_str: str) -> list[str]:
    """Return alphabetically-sorted free-symbol names in expr_str.

    Sympy's ``sympify`` distinguishes free symbols (variables) from
    known constants like ``pi``, ``E``, ``I`` and from function names
    like ``sin``, ``log``, so we get exactly the names that the
    generated function should accept as arguments.

    If you have a variable that collides with a sympy constant — the
    classic gotchas are ``E`` and ``I`` — pass an explicit ``params``
    list via the detailed JSON form below; auto-detect can't see them
    as free.
    """
    return sorted(str(s) for s in _sympify_chunked(expr_str).free_symbols)


def get_at_path(data, path):
    """Navigate ``data`` (a nested dict / list structure) along ``path``
    and return the value found there.

    ``path`` accepts two equivalent forms:

      1. Tuple / list of keys and indices, no ambiguity::

             get_at_path(d, ("formulas", "torque", "inputs"))
             get_at_path(d, ("schedule", 0, "value"))

      2. Dotted-with-bracket string for convenience::

             get_at_path(d, "formulas.torque.inputs")
             get_at_path(d, "schedule[0].value")

    Raises ``KeyError`` / ``IndexError`` / ``TypeError`` with a message
    that names the offending segment, so failures point straight at
    the wrong path component instead of leaving the caller to bisect.
    """
    if isinstance(path, str):
        segments = _parse_path_string(path)
    else:
        segments = tuple(path)

    cur = data
    for i, seg in enumerate(segments):
        try:
            cur = cur[seg]
        except (KeyError, IndexError, TypeError) as e:
            crumb = '.'.join(repr(s) for s in segments[:i + 1])
            raise type(e)(f"path lookup failed at segment {i} "
                          f"({crumb!r}): {e}") from None
    return cur


def _parse_path_string(s: str):
    """`"a.b[0].c"` → `("a", "b", 0, "c")`.  Tolerates absence of dot
    before a bracket: `a[0][1].b` works."""
    out: list = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '.':
            i += 1
            continue
        if s[i] == '[':
            j = s.index(']', i)
            tok = s[i + 1:j].strip()
            if not tok or not (tok.lstrip('-').isdigit()):
                raise ValueError(f"non-integer index in path: {s!r}")
            out.append(int(tok))
            i = j + 1
            continue
        # plain key — read up to next '.' or '['
        j = i
        while j < n and s[j] not in '.[':
            j += 1
        if j == i:
            raise ValueError(f"empty segment in path: {s!r}")
        out.append(s[i:j])
        i = j
    return tuple(out)


def _normalize_paths(p):
    """A single path (str or tuple) becomes ``[p]``; a list of paths is
    returned unchanged.  See :func:`get_at_path` for path syntax.

    Note the convention: a *tuple* of strings is one path with multiple
    segments (``("formulas", "torque")``); a *list* of strings is
    several single-segment paths (``["inputs", "constants"]``).
    """
    if isinstance(p, (str, tuple)):
        return [p]
    if isinstance(p, list):
        if not all(isinstance(x, (str, tuple)) for x in p):
            raise TypeError(f"list of paths must contain only str or tuple "
                            f"elements, got {p!r}")
        return p
    raise TypeError(f"path argument must be str / tuple / list, "
                    f"got {type(p).__name__}")


def _merge_dicts_at(data, path_or_paths, label: str) -> dict:
    """Read one or more dicts from ``data`` (each at a path supplied
    by ``path_or_paths``) and return a single merged dict.  Raises
    ``ValueError`` if any key appears in more than one source — silent
    overwrites would mask a real schema error.

    ``label`` is just used in the error message ("constants" /
    "subexprs") so the caller can tell which group complained.
    """
    merged: dict = {}
    for path in _normalize_paths(path_or_paths):
        chunk = get_at_path(data, path)
        if not isinstance(chunk, dict):
            raise TypeError(f"{label} at {path!r} must be a dict, "
                            f"got {type(chunk).__name__}")
        overlap = set(merged) & set(chunk)
        if overlap:
            raise ValueError(f"{label} name(s) {sorted(overlap)} appear "
                             f"in multiple paths within {label}_at — "
                             f"keep names disjoint across the sources")
        merged.update(chunk)
    return merged


def _expand_subexprs(expr_str: str, subexprs: dict) -> str:
    """Resolve named sub-expressions into ``expr_str`` so the result is
    a single self-contained expression that :func:`make_expr_func` can
    compile.

    ``subexprs`` is a ``{name: expression_str}`` dict; entries may
    reference each other.  Substitution is done at the sympy AST level
    (``xreplace``), not as text, so a name being a substring of another
    identifier is not a hazard.

    Iterate to a fixed point so chains like ``a -> b -> c`` resolve in
    one call.  Cycles raise ``ValueError``.

    Note: this is purely an *input-side* convenience — sympy's CSE
    pass inside :func:`make_expr_func` will rediscover any common
    subexpression in the inlined formula, so you pay no runtime cost
    for naming them in JSON.
    """
    sub_dict = {sp.Symbol(name): sp.sympify(expr) for name, expr in subexprs.items()}

    # Resolve sub_dict against itself — depth bounded by len(sub_dict),
    # so a normal chain converges within that many iterations.
    for _ in range(len(sub_dict) + 1):
        changed = False
        for sym, expr in list(sub_dict.items()):
            new_expr = expr.xreplace(sub_dict)
            if new_expr != expr:
                sub_dict[sym] = new_expr
                changed = True
        if not changed:
            break

    # A cycle converges too — to a pathological state where some entry
    # still resolves to one of the subexpr names (e.g. ``{a: b, b: a}``
    # settles at ``a -> a, b -> a``).  Catch that by checking for any
    # surviving subexpr-name references in the resolved values.
    sub_names = set(sub_dict)
    for sym, expr in sub_dict.items():
        leftover = expr.free_symbols & sub_names
        if leftover:
            raise ValueError(
                f"subexpression cycle: {sym} still depends on "
                f"{sorted(str(s) for s in leftover)} after substitution")

    return str(_sympify_chunked(expr_str).xreplace(sub_dict))


def _substitute_constants(expr_str: str, constants: dict) -> str:
    """Bake numeric constants into ``expr_str`` so they appear as
    literal values in the compiled code instead of function arguments.

    Substitution is at the sympy AST level, so a constant whose name
    happens to be a substring of another identifier (e.g. constant
    ``k`` inside variable ``key``) is unaffected.

    Precision handling.  String-form values (``"0.833333333333"``) are
    fed directly to ``sp.Float``, which picks an internal precision
    matching the digit count — this is how :func:`make_expr_func_from_json`
    avoids the IEEE-754 round trip when called via the
    ``parse_float=str`` JSON loader.  Native float values are accepted
    too but are bounded by Python's float precision (~15-17 sig figs).
    Ints become ``sp.Integer``.
    """
    sub_dict: dict = {}
    for name, value in constants.items():
        if isinstance(value, bool):  # bool is an int subclass — exclude
            raise TypeError(f"constant {name!r}: bool is not a numeric value")
        if isinstance(value, str):
            sub_dict[sp.Symbol(name)] = sp.Float(value)
        elif isinstance(value, float):
            sub_dict[sp.Symbol(name)] = sp.Float(value)
        elif isinstance(value, int):
            sub_dict[sp.Symbol(name)] = sp.Integer(value)
        else:
            raise TypeError(f"constant {name!r} must be int / float / "
                            f"numeric-string, got {type(value).__name__}")
    return str(_sympify_chunked(expr_str).xreplace(sub_dict))


def make_expr_func_from_json(json_path, expr_at, *,
                             constants_at=None, subexprs_at=None,
                             params_at=None, **compile_opts):
    """One-shot: read an expression at ``expr_at``, optionally inline
    named sub-expressions and bake in numeric constants, then return
    the compiled callable.

    Path arguments accept the same forms as :func:`get_at_path` —
    tuples or dotted-with-bracket strings.

    Constants
    ---------
    ``constants_at`` points to a ``{name: number}`` dict.  Each entry
    is substituted into the expression as a numeric literal at compile
    time, so it never appears as a function argument::

        "constants": {"k1": 6.5e-5, "k2": 0.001}

    A *list* of paths is also accepted; each path's value is read as
    its own ``{name: number}`` dict and they're merged.  Useful when
    the schema splits constants across categories::

        constants_at = ["physics_consts", "calibration_consts"]

    Names must be disjoint across the merged sources — overlap raises
    ``ValueError`` so silent overrides don't slip through.

    Sub-expressions
    ---------------
    ``subexprs_at`` points to a ``{name: expr_string}`` dict.  Each
    named expression is inlined into the main formula before
    compilation.  Entries may reference each other and may reference
    constants defined in ``constants_at``; resolution is iterative,
    cycles are caught.

    Same multi-path form is accepted as for ``constants_at``.

    Parameters (variables)
    ----------------------
    By default, the function's parameters are whatever free symbols
    remain after constant + sub-expression substitution, sorted
    alphabetically — convenient when variable names aren't pinned in
    the JSON ahead of time.

    Pass ``params_at`` (path / list of paths to lists of strings) to
    pin a non-alphabetical positional order.  When given, the listed
    names must be a superset of the surviving free symbols.

    Example.  Given ``config.json``::

        {
          "constants": {"k1": 6.5e-5, "k2": 0.001},
          "subexprs":  {"power": "v*i"},
          "formula":   "0.5*power - k1*v**2 - k2*i**2"
        }

    compile and call::

        f = make_expr_func_from_json(
            "config.json",
            expr_at      = "formula",
            constants_at = "constants",
            subexprs_at  = "subexprs",
        )
        f(1.5, 220.0)                # auto-detected order: i, v

    Names should be disjoint across constants / subexprs / params; if
    they overlap, sub-expression definitions win over constant values
    (subexprs are inlined first).

    Precision
    ---------
    The JSON loader uses ``parse_float=str`` so floats arrive at
    :func:`_substitute_constants` as their original textual form.
    A constant written as ``0.833333333333`` (12 digits) is preserved
    exactly through to the generated code, instead of being rounded
    to Python's default 15-significant-digit display.  Beyond ~17
    digits the runtime is still bounded by IEEE-754 doubles — the
    digits past that survive in the generated source for traceability
    but the executed computation is double-precision.

    ``compile_opts`` are forwarded to :func:`make_expr_func`
    (``jit``, ``fastmath``, ``cache``, ``debug``).
    """
    # ---- main thread: cheap I/O, path lookups, dict merging, type checks
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh, parse_float=str)

    expr_str = get_at_path(data, expr_at)
    if not isinstance(expr_str, str):
        raise TypeError(f"expr at {expr_at!r} must be a string, "
                        f"got {type(expr_str).__name__}")

    subexprs = None
    if subexprs_at is not None:
        subexprs = _merge_dicts_at(data, subexprs_at, "subexprs")
        if not all(isinstance(k, str) and isinstance(v, str)
                   for k, v in subexprs.items()):
            raise TypeError(f"subexprs at {subexprs_at!r} must map "
                            f"str -> str")

    constants = None
    if constants_at is not None:
        constants = _merge_dicts_at(data, constants_at, "constants")

    params_explicit = None
    if params_at is not None:
        params_explicit = []
        for path in _normalize_paths(params_at):
            chunk = get_at_path(data, path)
            if not (isinstance(chunk, list)
                    and all(isinstance(p, str) for p in chunk)):
                raise TypeError(f"params at {path!r} must be a list of "
                                f"strings, got {type(chunk).__name__}")
            params_explicit.extend(chunk)

    debug = compile_opts.pop('debug', False)
    jit = compile_opts.pop('jit', True)
    fastmath = compile_opts.pop('fastmath', True)
    cache = compile_opts.pop('cache', True)
    if compile_opts:
        raise TypeError(f"unexpected keyword arguments: "
                        f"{sorted(compile_opts)}")

    # ---- worker thread: every sympy call lives inside the big stack +
    #      elevated recursionlimit.  sympify itself is recursion-heavy
    #      on long inputs, so substitutions (which call sympify on the
    #      whole formula) MUST happen here, not in the main thread.
    def _heavy():
        import sys
        old_limit = sys.getrecursionlimit()
        if old_limit < 1_000_000:
            sys.setrecursionlimit(1_000_000)
        try:
            return _compile_with_subst(
                formula=expr_str,
                params_explicit=params_explicit,
                constants=constants,
                subexprs=subexprs,
                debug=debug,
            )
        finally:
            sys.setrecursionlimit(old_limit)

    fn = _run_in_big_stack(_heavy, stack_mb=256)

    if jit:
        from numba import njit
        fn = njit(cache=cache, fastmath=fastmath)(fn)
    return fn


def make_expr_funcs_from_json(json_path, exprs_at, *,
                              constants_at=None, subexprs_at=None,
                              params_at=None, progress=False,
                              **compile_opts):
    """Plural version of :func:`make_expr_func_from_json`: compile
    *every* formula in the dict at ``exprs_at`` using one shared set
    of constants and sub-expressions.

    Returns ``{name: callable}`` keyed by the dict's keys.

    Why not just call the singular version in a loop?

      - JSON is loaded once, not N times
      - constants and subexprs dicts are merged once
      - all formulas compile inside a single worker thread, so the
        big-stack / high-recursion setup is paid once
      - generated source files (under tempdir/expr_compiler_gen/) are
        deduped by content hash across all formulas

    Path arguments accept the same forms as :func:`get_at_path`.

    ``exprs_at`` must point to a ``{name: formula_string}`` dict::

        {
          "constants": {"k": 6.5e-5},
          "subexprs":  {"power": "v*i"},
          "exprs": {
            "f1": "0.5*power - k*v**2",
            "f2": "power**2 + k*i",
            "f3": "..."
          }
        }

        funcs = make_expr_funcs_from_json(
            "config.json",
            exprs_at     = "exprs",
            constants_at = "constants",
            subexprs_at  = "subexprs",
        )
        funcs["f1"](1.5, 220.0)
        funcs["f2"](1.5, 220.0)

    Each formula independently auto-detects its own free symbols
    (alphabetical) — different formulas may have different parameter
    sets and that's fine.

    If you pass ``params_at``, the listed names are used as the
    positional-argument order for *every* compiled function: each
    formula's free symbols must be a subset of the list, and any
    listed name not used by a particular formula becomes an unused
    parameter of that function (handy when you want a uniform call
    signature across the batch).

    Progress reporting
    ------------------
    For batches of hundreds of formulas the first run can take
    minutes; pass ``progress=True`` to get a periodic stderr
    dump showing throughput, cache hit rate, and ETA::

        [expr_compiler] 1/247 (0%)   cache hits: 0/1   elapsed 0.4s   ETA 99s
        [expr_compiler] 50/247 (20%) cache hits: 47/50 elapsed 1.2s   ETA 4.6s
        [expr_compiler] 247/247 (100%) cache hits: 240/247 elapsed 4.3s ETA 0.0s

    Pass a callable instead of ``True`` to log to your own sink —
    it's invoked after each formula completes with a dict::

        {
          'name': <key>,
          'done': <int>,    'total': <int>,
          'elapsed': <s>,   'duration': <s>,
          'cache_hit': <bool>, 'cache_hits': <int>,
        }

    Useful for capturing per-formula timings::

        timings = []
        funcs = make_expr_funcs_from_json(
            ..., progress=lambda info: timings.append(info))
        slowest = sorted(timings, key=lambda i: i['duration'])[-5:]

    ``compile_opts`` are forwarded to :func:`make_expr_func`
    (``jit``, ``fastmath``, ``cache``, ``debug``); they apply to
    every compiled function.
    """
    # ---- main thread: cheap I/O, path lookups, dict merging, type checks
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh, parse_float=str)

    exprs = get_at_path(data, exprs_at)
    if not isinstance(exprs, dict):
        raise TypeError(f"exprs at {exprs_at!r} must be a dict, "
                        f"got {type(exprs).__name__}")
    if not all(isinstance(k, str) and isinstance(v, str)
               for k, v in exprs.items()):
        raise TypeError(f"exprs at {exprs_at!r} must map "
                        f"str -> str (formula strings)")

    subexprs = None
    if subexprs_at is not None:
        subexprs = _merge_dicts_at(data, subexprs_at, "subexprs")
        if not all(isinstance(k, str) and isinstance(v, str)
                   for k, v in subexprs.items()):
            raise TypeError(f"subexprs at {subexprs_at!r} must map "
                            f"str -> str")

    constants = None
    if constants_at is not None:
        constants = _merge_dicts_at(data, constants_at, "constants")

    params_explicit = None
    if params_at is not None:
        params_explicit = []
        for path in _normalize_paths(params_at):
            chunk = get_at_path(data, path)
            if not (isinstance(chunk, list)
                    and all(isinstance(p, str) for p in chunk)):
                raise TypeError(f"params at {path!r} must be a list of "
                                f"strings, got {type(chunk).__name__}")
            params_explicit.extend(chunk)

    debug = compile_opts.pop('debug', False)
    jit = compile_opts.pop('jit', True)
    fastmath = compile_opts.pop('fastmath', True)
    cache = compile_opts.pop('cache', True)
    if compile_opts:
        raise TypeError(f"unexpected keyword arguments: "
                        f"{sorted(compile_opts)}")

    # ---- worker thread: compile every formula serially with one
    #      stack/recursion setup.  _compile_with_subst is content-
    #      addressed-cached, so re-running with an unchanged JSON
    #      hits the cache for every formula and only the first
    #      invocation pays the sympy cost.
    def _heavy():
        import sys
        import time
        old_limit = sys.getrecursionlimit()
        if old_limit < 1_000_000:
            sys.setrecursionlimit(1_000_000)
        try:
            out: dict = {}
            n_total = len(exprs)
            n_done = 0
            n_hit = 0
            t_start = time.perf_counter()
            t_last_log = t_start

            for name, formula in exprs.items():
                t_entry = time.perf_counter()

                # Cache-hit check before compiling so the progress
                # report can show how much sympy work was actually
                # done vs. saved.
                cache_key = _compute_compile_key(
                    formula, params_explicit, constants, subexprs)
                was_hit = os.path.exists(_cache_path_for_key(cache_key))
                if was_hit:
                    n_hit += 1

                out[name] = _compile_with_subst(
                    formula=formula,
                    params_explicit=params_explicit,
                    constants=constants,
                    subexprs=subexprs,
                    debug=debug,
                )
                n_done += 1

                if progress:
                    now = time.perf_counter()
                    info = {
                        'name':       name,
                        'done':       n_done,
                        'total':      n_total,
                        'elapsed':    now - t_start,
                        'duration':   now - t_entry,
                        'cache_hit':  was_hit,
                        'cache_hits': n_hit,
                    }
                    if callable(progress):
                        progress(info)
                    elif progress is True:
                        # Throttle stderr to ~1 line/sec, but always
                        # print first and last so short batches still
                        # produce some output.
                        if (now - t_last_log >= 1.0
                                or n_done == 1
                                or n_done == n_total):
                            eta = (info['elapsed'] / n_done
                                   * (n_total - n_done)
                                   if n_done < n_total else 0.0)
                            pct = n_done * 100.0 / n_total
                            print(f"[expr_compiler] {n_done}/{n_total} "
                                  f"({pct:.0f}%)  "
                                  f"cache hits: {n_hit}/{n_done}  "
                                  f"elapsed {info['elapsed']:.1f}s  "
                                  f"ETA {eta:.1f}s",
                                  file=sys.stderr, flush=True)
                            t_last_log = now
            return out
        finally:
            sys.setrecursionlimit(old_limit)

    pyfns = _run_in_big_stack(_heavy, stack_mb=256)

    if jit:
        import sys as _sys
        import time as _time
        if progress is True:
            print(f"[expr_compiler] applying numba JIT decoration to "
                  f"{len(pyfns)} functions...",
                  file=_sys.stderr, flush=True)
        t_jit = _time.perf_counter()
        from numba import njit
        for name in list(pyfns):
            pyfns[name] = njit(cache=cache, fastmath=fastmath)(pyfns[name])
        if progress is True:
            print(f"[expr_compiler] JIT decoration done in "
                  f"{_time.perf_counter() - t_jit:.2f}s "
                  f"(actual machine-code compile is lazy on first call)",
                  file=_sys.stderr, flush=True)
    return pyfns


def compile_expressions_in_data(data, is_expr, **compile_opts):
    """Walk a JSON-like nested structure (dicts, lists, primitives)
    and compile only the leaves identified by ``is_expr`` as math
    expressions.  Returns a NEW structure mirroring ``data`` with
    matched leaves replaced by callables; everything else passes
    through unchanged.

    Parameters
    ----------
    data : dict | list | scalar
        Anything ``json.load`` can produce.  Walked recursively.
    is_expr : callable(path, value) -> bool
        Predicate run on every leaf.  ``path`` is a tuple of dict keys
        (str) and list indices (int) leading to the value; ``value``
        is the leaf itself.  Return True iff the leaf is a math
        expression that should be compiled.
    **compile_opts
        Forwarded to :func:`make_expr_func` (``jit``, ``fastmath``,
        ``cache``, ``debug``).

    Useful predicate shapes::

        # Any string under a key named "formula" / "expr":
        lambda p, v: isinstance(v, str) and p and p[-1] in ("formula", "expr")

        # Sentinel-prefix convention "=expression":
        lambda p, v: isinstance(v, str) and v.startswith("=")
        # (then strip the "=" yourself before passing to make_expr_func —
        #  or use the load_expressions_from_json marker= helper below)

        # Specific paths only:
        lambda p, v: p == ("device", "transfer_func")

        # Nested under a "formulas" subtree, regardless of inner key:
        lambda p, v: isinstance(v, str) and len(p) >= 1 and p[0] == "formulas"

    Returned structure example::

        in:  {"name": "x", "max_v": 220,
              "calc": {"f": "a*b + c"}, "schedule": [{"v": "x*2"}]}
        out: {"name": "x", "max_v": 220,
              "calc": {"f": <fn(a,b,c)>}, "schedule": [{"v": <fn(x)>}]}
    """
    def _walk(node, path):
        if isinstance(node, dict):
            return {k: _walk(v, path + (k,)) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v, path + (i,)) for i, v in enumerate(node)]
        if is_expr(path, node):
            if not isinstance(node, str):
                raise TypeError(
                    f"is_expr returned True for non-string at path {path!r}: "
                    f"{type(node).__name__} (only strings can be compiled)")
            params = _detect_params(node)
            return make_expr_func(node, params, **compile_opts)
        return node

    return _walk(data, ())


def load_expressions_from_json(json_path: str | Path, is_expr,
                               **compile_opts):
    """Convenience: open ``json_path``, parse, walk via
    :func:`compile_expressions_in_data`, return the compiled
    structure."""
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh)
    return compile_expressions_in_data(data, is_expr, **compile_opts)


def make_funcs_from_json(json_path: str | Path, **compile_opts) -> dict:
    """Read formulas from a JSON file and compile each one.

    Returns a ``{name: callable}`` mapping.  ``compile_opts`` are
    forwarded to :func:`make_expr_func` (``jit``, ``fastmath``,
    ``cache``, ``debug``).

    Two JSON layouts are supported and may be mixed in a single file:

    1. **Flat** — name keys map directly to expression strings.
       Parameter order is auto-detected alphabetically from each
       expression::

           {
               "torque":   "0.5 * m * r**2 * omega",
               "voltage":  "I * R + L * dI_dt"
           }

    2. **Detailed** — name keys map to objects with an ``expr`` field
       and an optional ``params`` field that controls positional
       argument order::

           {
               "torque": {
                   "expr":   "0.5 * m * r**2 * omega",
                   "params": ["m", "r", "omega"]
               }
           }

       Use the detailed form when you need a non-alphabetical arg
       order, or when a variable's name collides with a sympy
       constant (``E``, ``I``, ``pi`` …) and auto-detection would
       miss it.

    Raises ``ValueError`` / ``TypeError`` on a malformed file with a
    message identifying the offending entry.
    """
    path = Path(json_path)
    with path.open(encoding='utf-8') as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise TypeError(f"{path}: top-level JSON must be an object, "
                        f"got {type(data).__name__}")

    funcs: dict = {}
    for name, entry in data.items():
        if isinstance(entry, str):
            expr_str = entry
            params = _detect_params(expr_str)
        elif isinstance(entry, dict) and 'expr' in entry:
            expr_str = entry['expr']
            if not isinstance(expr_str, str):
                raise TypeError(f"{name}: 'expr' must be a string, "
                                f"got {type(expr_str).__name__}")
            params = entry.get('params')
            if params is None:
                params = _detect_params(expr_str)
            elif not (isinstance(params, list)
                      and all(isinstance(p, str) for p in params)):
                raise TypeError(f"{name}: 'params' must be a list of strings")
        else:
            raise TypeError(
                f"{name}: entry must be either an expression string or an "
                f"object with an 'expr' field, got {type(entry).__name__}")

        funcs[name] = make_expr_func(expr_str, params, **compile_opts)

    return funcs


