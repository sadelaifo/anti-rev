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
import json
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
    """The recursion-heavy part of make_expr_func, isolated so it can
    run inside _run_in_big_stack.  Returns a plain Python function;
    JIT decoration happens in the caller."""
    import sys
    old_limit = sys.getrecursionlimit()
    if old_limit < 1_000_000:
        sys.setrecursionlimit(1_000_000)
    try:
        # 1. sympify — bind variable names to sympy Symbols so they're
        #    not misread as imports or function names.  Empty params
        #    (a constant expression) is allowed; sp.symbols('') errors.
        if params:
            syms = sp.symbols(' '.join(params))
            if not isinstance(syms, tuple):
                syms = (syms,)
        else:
            syms = ()
        expr = _sympify_chunked(expr_str, dict(zip(params, syms)))

        # 2. CSE — find repeated subterms across the whole expression
        #    and replace them with intermediates.  ``optimizations=
        #    'basic'`` runs a couple of pre-CSE algebraic passes that
        #    are O(N²)-ish on very wide Adds and dominate compile time
        #    for 10k+ term inputs while finding little extra savings
        #    on engineering polynomials.  Skip them past ~10k args.
        opt_level = 'basic' if not (
            isinstance(expr, sp.Add) and len(expr.args) > 10_000
        ) else None
        sub_exprs, [main] = sp.cse(expr, optimizations=opt_level)

        # 3. Generate Python source.  Top-level Adds with many terms
        #    are split into chunked partial sums so the final return's
        #    AST stays shallow — cuts CPython's parse depth from O(N)
        #    to O(sqrt(N)) on big polynomials.
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

        # 4. exec — CPython parses left-recursive chains by recursing
        #    on every operator; the chunked source keeps each line
        #    short, but we still bump the limit as a safety belt.
        ns: dict = {}
        exec(src, ns)
        return ns['_expr']
    finally:
        sys.setrecursionlimit(old_limit)


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
            e = expr_str
            if subexprs is not None:
                e = _expand_subexprs(e, subexprs)
            if constants is not None:
                e = _substitute_constants(e, constants)
            p = (params_explicit if params_explicit is not None
                 else _detect_params(e))
            return _compile_pyfunc(e, p, debug=debug)
        finally:
            sys.setrecursionlimit(old_limit)

    fn = _run_in_big_stack(_heavy, stack_mb=256)

    if jit:
        from numba import njit
        fn = njit(cache=cache, fastmath=fastmath)(fn)
    return fn


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


