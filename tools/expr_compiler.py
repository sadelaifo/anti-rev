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
(e.g. ``x*y``, ``x**2``) appears in many places.  numba is a
meaningful win for high-frequency calls; if you're calling once per
batch on numpy arrays, prefer ``numexpr.evaluate`` instead — different
optimisation regime.

Public API:

    f = make_expr_func("a*b + c**2", ["a", "b", "c"])
    f(1.0, 2.0, 3.0)

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
    # 1. sympify — bind variable names to sympy Symbols so they're not
    #    misread as imports or function names.
    syms = sp.symbols(' '.join(params))
    if not isinstance(syms, tuple):       # single-param case
        syms = (syms,)
    expr = sp.sympify(expr_str, locals=dict(zip(params, syms)))

    # 2. CSE — let sympy find repeated subterms across the whole expression
    #    and replace them with intermediates.  cheap on small/medium expr;
    #    on multi-thousand-term inputs you may want optimizations=[] to
    #    skip the more expensive passes.
    sub_exprs, [main] = sp.cse(expr, optimizations='basic')

    # 3. Generate Python source.  sp.pycode is stricter than str() — it
    #    won't emit Rational(1,2) or other sympy-specific literals that
    #    Python can't parse.
    lines = [f"def _expr({', '.join(params)}):"]
    for tmp, val in sub_exprs:
        lines.append(f"    {tmp} = {sp.pycode(val)}")
    lines.append(f"    return {sp.pycode(main)}")
    src = "\n".join(lines) + "\n"

    if debug:
        print("--- generated source ---")
        print(src)
        print(f"--- {len(sub_exprs)} CSE temps ---")

    ns: dict = {}
    exec(src, ns)
    fn = ns['_expr']

    # 4. numba JIT.  Imported lazily so the pure-Python path doesn't pay
    #    the import cost when jit=False.
    if jit:
        from numba import njit
        fn = njit(cache=cache, fastmath=fastmath)(fn)

    return fn


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
    return sorted(str(s) for s in sp.sympify(expr_str).free_symbols)


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


def make_expr_func_from_json(json_path, expr_at, params_at, **compile_opts):
    """One-shot: read an expression string at ``expr_at`` and a
    parameter-name list at ``params_at`` from the same JSON file,
    return the compiled callable.

    Both ``expr_at`` and ``params_at`` accept the same path forms as
    :func:`get_at_path` — tuples or dotted-with-bracket strings.

    Example.  Given ``config.json``::

        {
          "device": {
            "transfer": {
              "formula": "0.5*v*i + k*v**2",
              "inputs":  ["v", "i", "k"]
            }
          }
        }

    compile with::

        f = make_expr_func_from_json(
            "config.json",
            expr_at   = "device.transfer.formula",
            params_at = "device.transfer.inputs",
        )
        result = f(220.0, 1.5, 1.2e-5)

    ``compile_opts`` are forwarded to :func:`make_expr_func`
    (``jit``, ``fastmath``, ``cache``, ``debug``).
    """
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh)

    expr = get_at_path(data, expr_at)
    if not isinstance(expr, str):
        raise TypeError(f"expr at {expr_at!r} must be a string, "
                        f"got {type(expr).__name__}")

    params = get_at_path(data, params_at)
    if not (isinstance(params, list)
            and all(isinstance(p, str) for p in params)):
        raise TypeError(f"params at {params_at!r} must be a list of strings, "
                        f"got {type(params).__name__}")

    return make_expr_func(expr, params, **compile_opts)


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


# ---------------------------------------------------------------------
# Demo / micro-benchmark when run as a script.
# ---------------------------------------------------------------------
def _demo() -> None:
    import random
    import time

    expr = ("-.5e-12*x**7*y**2*z + .18188888*x "
            "+ 1.7e-9*x**3*y**3 - 0.001*x*y*z "
            "+ 4.2e-6*x**2*z**2 + 0.5e-3*y**4")
    params = ["x", "y", "z"]

    f_py = make_expr_func(expr, params, jit=False, debug=True)
    try:
        f_jit = make_expr_func(expr, params, jit=True)
    except ImportError:
        print("(numba not installed — skipping JIT path)")
        f_jit = None

    # Correctness sanity check
    if f_jit is not None:
        f_jit(1.0, 2.0, 3.0)              # warm up the JIT compile
        for _ in range(50):
            a = random.uniform(0.1, 10)
            b = random.uniform(0.1, 10)
            c = random.uniform(0.1, 10)
            v_py = f_py(a, b, c)
            v_jit = f_jit(a, b, c)
            assert abs(v_py - v_jit) < 1e-9 * (abs(v_py) + 1.0), \
                f"py vs jit mismatch at ({a},{b},{c}): {v_py} vs {v_jit}"
        print("correctness check: OK")

    # Micro-benchmark
    N = 1_000_000
    t0 = time.perf_counter()
    for _ in range(N):
        f_py(1.0, 2.0, 3.0)
    t_py = time.perf_counter() - t0

    print(f"pure Python (exec'd): {t_py * 1e9 / N:8.1f} ns/call  "
          f"({N / t_py / 1e6:.2f} M calls/s)")

    if f_jit is not None:
        t0 = time.perf_counter()
        for _ in range(N):
            f_jit(1.0, 2.0, 3.0)
        t_jit = time.perf_counter() - t0
        print(f"numba JIT:            {t_jit * 1e9 / N:8.1f} ns/call  "
              f"({N / t_jit / 1e6:.2f} M calls/s)")
        print(f"speedup:              {t_py / t_jit:.1f}x")


def _compile_json_cli(json_path: str) -> None:
    """Compile every formula in a JSON file and print a summary.
    Useful as a sanity check before wiring the compiled funcs into a
    real workload — a malformed expression / missing param will surface
    here instead of mid-batch."""
    funcs = make_funcs_from_json(json_path)
    print(f"compiled {len(funcs)} formula(s) from {json_path}:")
    for name, fn in funcs.items():
        # Underlying compiled function lives at fn.py_func when JIT'd,
        # otherwise just fn.  Reach for the param names via __code__.
        py_fn = getattr(fn, 'py_func', fn)
        names = list(py_fn.__code__.co_varnames[:py_fn.__code__.co_argcount])
        print(f"  {name}({', '.join(names)})")


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        _compile_json_cli(sys.argv[1])
    else:
        _demo()
