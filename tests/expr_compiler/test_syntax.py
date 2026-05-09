#!/usr/bin/env python3
"""Syntax / precedence cross-check for tools/expr_compiler.make_expr_func.

For each interesting expression form (parenthesised precedence, leading-
dot scientific notation, ``**`` power, identifiers-with-digits, mixed),
compile it through ``make_expr_func`` and compare the result to Python's
native ``eval()`` of the same string at the same point.  If sympy's
parser interprets the syntax differently from Python, this test fails
loudly with the offending expression.

Run from the project root::

    python3 tests/expr_compiler/test_syntax.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import make_expr_func  # noqa: E402

# Each case: (label, expr_str, sample_values_dict)
# sample_values_dict's keys define the parameter list; an empty dict
# means a constant expression.
CASES: list[tuple[str, str, dict]] = [
    # --- basic precedence & parentheses -------------------------------
    ("no parens, *-+ precedence",
     "2*3 + 4",                       {}),
    ("parens override precedence",
     "2*(3 + 4)",                     {}),
    ("nested parens",
     "((1 + 2) * (3 + 4)) - 5",       {}),
    ("unary minus + parens",
     "-(2 + 3)*4",                    {}),

    # --- ** power operator --------------------------------------------
    ("** higher than *",
     "2 * 3**2",                      {}),
    ("parens around base of **",
     "(2 + 1)**2",                    {}),
    ("right-associative **",
     "2**3**2",                       {}),       # = 2**(3**2) = 512
    ("var ** int",
     "var1**2",                       {"var1": 1.5}),
    ("var ** float",
     "x**0.5",                        {"x": 4.0}),
    ("(a+b)**2 expansion",
     "(a + b)**2",                    {"a": 1.5, "b": 2.5}),

    # --- scientific notation ------------------------------------------
    ("plain scinot",
     "1.5e3 + 1",                     {}),
    ("negative-exponent scinot",
     "1.5e-3 * 1000",                 {}),
    ("leading-dot scinot (no leading zero)",
     ".5e12",                         {}),
    ("negative leading-dot scinot",
     "-.5e12",                        {}),
    ("neg-coef scinot * int",
     "-.11111e-1 * 2",                {}),
    ("scinot mixed with var",
     "-.5e-12*x + .18188888*x",       {"x": 1234.5}),

    # --- identifiers with digits + underscores ------------------------
    ("var1, var2 with **",
     "var1**2 + var2**3 - .5e-3*var1",  {"var1": 1.5, "var2": 2.0}),
    ("underscore identifier",
     "x_1**2 + y_long_name",          {"x_1": 3.0, "y_long_name": 7.0}),

    # --- the canonical messy expression -------------------------------
    ("messy realistic",
     "-.5e-12*x**7*y**2*z + .18188888*x + 1.7e-9*x**3*y**3"
     " - 0.001*x*y*z + 4.2e-6*x**2*z**2 + 0.5e-3*y**4",
     {"x": 2.5, "y": 3.5, "z": 4.5}),
]


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def long_expression_check() -> int:
    """Regression check: a few-hundred-term polynomial should compile
    without hitting CPython's recursion limit during exec().  Default
    sys.recursionlimit is 1000, so a return line with > ~500 chained
    additions used to crash with `RecursionError: ... during
    compilation` on the AST build of the generated source.
    """
    n = 600
    sample = {"x": 1.5, "y": 2.5}
    # 600 terms of the form `c_i * x**i * y**(n-i)`, simple enough that
    # eval() can also handle it for cross-checking.
    expr = " + ".join(f"{(i + 1) * 1e-9} * x**{i % 5} * y**{(i + 7) % 4}"
                      for i in range(n))
    print(f"  long-expr: {n} terms, source length ~{len(expr)} chars")

    try:
        ref = eval(expr, {"__builtins__": {}}, sample)
    except RecursionError:
        # Even Python's own eval may need a higher recursion limit on
        # this length — bump for the reference path too.
        import sys as _sys
        old = _sys.getrecursionlimit()
        _sys.setrecursionlimit(50_000)
        try:
            ref = eval(expr, {"__builtins__": {}}, sample)
        finally:
            _sys.setrecursionlimit(old)

    f = make_expr_func(expr, sorted(sample), jit=False)
    got = f(*[sample[k] for k in sorted(sample)])
    if not near(float(got), float(ref)):
        print(f"  [FAIL] long-expr value mismatch: {got} vs {ref}")
        return 1
    print(f"  [OK]   long-expr compiled and evaluated correctly: {got}")
    return 0


def main() -> int:
    failures = 0
    for label, expr, sample in CASES:
        # Reference: Python's own parser + evaluator on the same string.
        try:
            ref = eval(expr, {"__builtins__": {}}, sample)
        except Exception as e:
            print(f"  [SKIP] {label!r}: Python eval rejected: {e}")
            continue

        # System under test: compile and call.
        params = sorted(sample.keys())
        try:
            f = make_expr_func(expr, params, jit=False)
        except Exception as e:
            print(f"  [FAIL] {label!r}: compile error: {e}")
            print(f"         expr:   {expr!r}")
            failures += 1
            continue

        args = [sample[k] for k in params]
        got = f(*args)
        if not near(float(got), float(ref)):
            print(f"  [FAIL] {label!r}: {got} != {ref}")
            print(f"         expr:   {expr!r}")
            print(f"         sample: {sample}")
            failures += 1
            continue
        print(f"  [OK]   {label:42s}  {expr!r}  -> {got}")

    print()
    failures += long_expression_check()
    total = len(CASES) + 1
    passed = total - failures
    print(f"[expr_compiler syntax test] {passed} / {total} passed.")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
