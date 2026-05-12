#!/usr/bin/env python3
"""nt/pt suffix shorthand expansion.

A variable named ``<prefix>nt`` represents ``<prefix> + <prefix>n``;
similarly ``<prefix>pt`` → ``<prefix> + <prefix>p``.  Examples::

    aaxnt = aax + aaxn
    aa1pt = aa1 + aa1p

Domain convention: ``nt`` / ``pt`` mark a "total" quantity that is
the sum of a base value and its n / p-suffixed counterpart.  Saves
the user having to spell out the sum in every formula.

Run from the project root::

    python3 tests/expr_compiler/test_suffix.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    _detect_params,
    _expand_nt_pt_suffixes,
    make_expr_func,
)
import sympy as sp                       # noqa: E402


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def test_basic_expansion() -> int:
    """aaxnt → aax + aaxn at the sympy AST level."""
    expr = sp.sympify("aaxnt", locals={"aaxnt": sp.Symbol("aaxnt")})
    out = _expand_nt_pt_suffixes(expr)
    expected = sp.Symbol("aax") + sp.Symbol("aaxn")
    if out != expected:
        print(f"  [FAIL] aaxnt expanded to {out!r}, expected {expected!r}")
        return 1
    print(f"  [OK]   aaxnt → {out}")
    return 0


def test_pt_expansion() -> int:
    """aa1pt → aa1 + aa1p."""
    expr = sp.sympify("aa1pt", locals={"aa1pt": sp.Symbol("aa1pt")})
    out = _expand_nt_pt_suffixes(expr)
    expected = sp.Symbol("aa1") + sp.Symbol("aa1p")
    if out != expected:
        print(f"  [FAIL] aa1pt expanded to {out!r}, expected {expected!r}")
        return 1
    print(f"  [OK]   aa1pt → {out}")
    return 0


def test_non_suffix_untouched() -> int:
    """Names not ending in nt/pt are left alone."""
    for name in ("ax", "y", "abc", "aax", "p"):
        sym = sp.Symbol(name)
        out = _expand_nt_pt_suffixes(sym)
        if out != sym:
            print(f"  [FAIL] {name} got rewritten to {out!r}")
            return 1
    print(f"  [OK]   plain names (ax, y, abc, aax, p) untouched")
    return 0


def test_mixed_formula() -> int:
    """A real formula with both nt and pt vars resolves correctly."""
    f = make_expr_func("0.5*aaxnt + aa1pt", ["aax", "aaxn", "aa1", "aa1p"],
                       jit=False)
    # aaxnt = aax + aaxn = 1 + 2 = 3
    # aa1pt = aa1 + aa1p = 4 + 5 = 9
    # 0.5*3 + 9 = 10.5
    got = f(aax=1.0, aaxn=2.0, aa1=4.0, aa1p=5.0)
    if not near(got, 10.5):
        print(f"  [FAIL] mixed formula: got {got}, expected 10.5")
        return 1
    print(f"  [OK]   0.5*aaxnt + aa1pt = {got} (with aax=1, aaxn=2, aa1=4, aa1p=5)")
    return 0


def test_auto_detect_params() -> int:
    """_detect_params returns post-expansion free symbols."""
    got = _detect_params("aaxnt + aa1pt")
    expected = ["aa1", "aa1p", "aax", "aaxn"]
    if got != expected:
        print(f"  [FAIL] _detect_params returned {got}, expected {expected}")
        return 1
    print(f"  [OK]   _detect_params expands suffixes: {got}")
    return 0


def test_chained_suffix() -> int:
    """xntnt → xnt + xntn → (x + xn) + xntn."""
    expr = sp.sympify("xntnt", locals={"xntnt": sp.Symbol("xntnt")})
    out = _expand_nt_pt_suffixes(expr)
    # After fixed-point: xnt expands too → x + xn + xntn
    expected = sp.Symbol("x") + sp.Symbol("xn") + sp.Symbol("xntn")
    if sp.simplify(out - expected) != 0:
        print(f"  [FAIL] xntnt expanded to {out!r}, expected {expected!r}")
        return 1
    print(f"  [OK]   xntnt → {out} (chained suffix resolved)")
    return 0


def test_short_names_untouched() -> int:
    """'nt' alone (prefix empty) is left untouched — that's not a
    shorthand, just a name that happens to be nt."""
    sym = sp.Symbol("nt")
    out = _expand_nt_pt_suffixes(sym)
    if out != sym:
        print(f"  [FAIL] 'nt' was rewritten to {out!r}")
        return 1
    print(f"  [OK]   'nt' standalone untouched")
    return 0


def test_three_char_name() -> int:
    """3-char names like 'ant' / 'apt' DO expand (prefix='a')."""
    expr = sp.sympify("ant", locals={"ant": sp.Symbol("ant")})
    out = _expand_nt_pt_suffixes(expr)
    expected = sp.Symbol("a") + sp.Symbol("an")
    if out != expected:
        print(f"  [FAIL] 'ant' expanded to {out!r}, expected {expected!r}")
        return 1
    print(f"  [OK]   'ant' → {out} (1-char prefix works)")
    return 0


def main() -> int:
    failures = 0
    failures += test_basic_expansion()
    failures += test_pt_expansion()
    failures += test_non_suffix_untouched()
    failures += test_mixed_formula()
    failures += test_auto_detect_params()
    failures += test_chained_suffix()
    failures += test_short_names_untouched()
    failures += test_three_char_name()
    if failures == 0:
        print("\n[expr_compiler suffix test] all checks passed.")
        return 0
    print(f"\n[expr_compiler suffix test] {failures} check(s) failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
