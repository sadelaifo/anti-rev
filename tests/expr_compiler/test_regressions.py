#!/usr/bin/env python3
"""Regression tests for tools/expr_compiler.

Each block locks in the fix for a specific bug found in code review,
so future refactors can't silently re-introduce them.

Run from the project root::

    python3 tests/expr_compiler/test_regressions.py
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    _compute_compile_key,
    make_expr_func,
    verify,
)


def test_compile_key_distinguishes_empty_list_from_none() -> int:
    """Bug #1: ``params_explicit=[]`` was hashing under the same key
    as ``params_explicit=None`` because the cache-key builder used a
    truthiness check (``if params_explicit``) instead of
    ``is not None``.  ``[]`` and ``None`` produce *different*
    generated code when the formula has free symbols, so they need
    distinct keys."""
    formula = "a + b"
    key_none  = _compute_compile_key(formula, None,  None, None)
    key_empty = _compute_compile_key(formula, [],    None, None)
    key_named = _compute_compile_key(formula, ["a", "b"], None, None)
    if key_none == key_empty:
        print(f"  [FAIL] params_explicit=None and [] hash the same: {key_none}")
        return 1
    if key_named in (key_none, key_empty):
        print(f"  [FAIL] explicit names collide with None/[]")
        return 1
    print(f"  [OK]   params_explicit None / [] / [a,b] → 3 distinct keys")
    return 0


def test_params_must_be_superset_of_free_symbols() -> int:
    """Bug #2: ``make_expr_func("a + b + c", ["a", "b"])`` would
    compile silently and only NameError out at call time.  Should
    raise ValueError at compile time with a clear message naming the
    missing variable."""
    try:
        make_expr_func("a + b + c", ["a", "b"], jit=False)
    except ValueError as e:
        msg = str(e)
        if "c" not in msg:
            print(f"  [FAIL] error doesn't name the missing variable: {msg}")
            return 1
        print(f"  [OK]   missing variable caught at compile: {e}")
        return 0
    except Exception as e:
        print(f"  [FAIL] expected ValueError, got {type(e).__name__}: {e}")
        return 1
    print(f"  [FAIL] expected ValueError, function compiled without error")
    return 1


def test_extras_in_params_are_allowed() -> int:
    """The flip side of #2: extra names in params (beyond the actual
    free symbols) must NOT error — that's how the
    ``make_expr_funcs_from_json(..., params_at=...)`` uniform-
    signature mode works.  An unused parameter is fine."""
    try:
        f = make_expr_func("a + 1", ["a", "unused"], jit=False)
    except Exception as e:
        print(f"  [FAIL] extra params should be allowed, got "
              f"{type(e).__name__}: {e}")
        return 1
    result = f(2.0, 999.0)   # unused doesn't affect result
    if result != 3.0:
        print(f"  [FAIL] expected 3.0, got {result}")
        return 1
    print(f"  [OK]   extra unused parameter accepted: f(2.0, 999.0) = {result}")
    return 0


def test_verify_summary_distinguishes_skip_from_fail() -> int:
    """Bug #4: ``verify`` reported ``X/Y passed`` where Y included
    skipped records, making "1 OK + 2 SKIP" look like "1 pass / 2
    fail".  Should now show three-way tally OK / FAIL / SKIP."""
    f_good = make_expr_func("a + b", ["a", "b"], jit=False)
    f_bad  = make_expr_func("a + b", ["a", "b"], jit=False)

    funcs    = {"good": f_good, "bad": f_bad, "missing": f_good}
    formulas = {"good": "a + b", "bad":  "a * b"}   # bad's text disagrees
    sample   = {"a": 2.0, "b": 3.0}

    buf = io.StringIO()
    records = verify(funcs, formulas, sample, file=buf)
    out = buf.getvalue()

    # Expect exactly: 1 OK (good), 1 FAIL (bad), 1 SKIP (missing)
    n_ok   = sum(1 for r in records if r.get('ok'))
    n_skip = sum(1 for r in records if r.get('error'))
    n_fail = len(records) - n_ok - n_skip

    if (n_ok, n_fail, n_skip) != (1, 1, 1):
        print(f"  [FAIL] expected 1 OK / 1 FAIL / 1 SKIP, got "
              f"{n_ok} OK / {n_fail} FAIL / {n_skip} SKIP")
        print(f"  output was:\n{out}")
        return 1
    if "1 OK" not in out or "1 FAIL" not in out or "1 SKIP" not in out:
        print(f"  [FAIL] summary line should contain three-way counts; "
              f"got: {out.strip().splitlines()[-1]}")
        return 1
    print(f"  [OK]   summary distinguishes: "
          f"{out.strip().splitlines()[-1]}")
    return 0


def main() -> int:
    failures = 0
    failures += test_compile_key_distinguishes_empty_list_from_none()
    failures += test_params_must_be_superset_of_free_symbols()
    failures += test_extras_in_params_are_allowed()
    failures += test_verify_summary_distinguishes_skip_from_fail()

    if failures == 0:
        print("\n[expr_compiler regression test] all checks passed.")
        return 0
    print(f"\n[expr_compiler regression test] {failures} check(s) failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
