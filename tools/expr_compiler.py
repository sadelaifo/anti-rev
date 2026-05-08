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
(e.g. ``x*y``, ``erxg1**2``) appears in many places.  numba is a
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
# Demo / micro-benchmark when run as a script.
# ---------------------------------------------------------------------
def _demo() -> None:
    import random
    import time

    expr = ("-.5e-12*erxg1**7*eryg1**2*nvgz + .18188888*erxg1 "
            "+ 1.7e-9*erxg1**3*eryg1**3 - 0.001*erxg1*eryg1*nvgz "
            "+ 4.2e-6*erxg1**2*nvgz**2 + 0.5e-3*eryg1**4")
    params = ["erxg1", "eryg1", "nvgz"]

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


if __name__ == '__main__':
    _demo()
