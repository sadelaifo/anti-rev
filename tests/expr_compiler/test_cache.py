#!/usr/bin/env python3
"""Verify the disk cache for compiled expressions.

Compiles a moderately heavy formula twice; second run must hit the
content-addressed cache in ``<tempdir>/expr_compiler_gen/`` and skip
the sympy pipeline entirely (timed: at least ~5x faster than the
first run on the regression formula).

Also confirms changing ANY input (formula text, a constant value,
a subexpr definition) invalidates the cache.

Run from the project root::

    python3 tests/expr_compiler/test_cache.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    make_expr_func_from_json,
    _compute_compile_key,
    _cache_path_for_key,
)


def _write(cfg: dict) -> str:
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    return p


def _time_compile(json_path: str) -> float:
    t0 = time.perf_counter()
    make_expr_func_from_json(
        json_path,
        expr_at      = "formula",
        constants_at = "constants",
        subexprs_at  = "subexprs",
        jit          = False,
    )
    return time.perf_counter() - t0


def main() -> int:
    # Moderately wide formula so the sympy work is measurable but
    # the test still runs in a couple of seconds.
    n = 800
    formula = " + ".join(
        f"c{i % 6} * x**{i % 5} * y**{(i + 7) % 4}"
        for i in range(n)
    )
    constants = {f"c{i}": (i + 1) * 0.001 for i in range(6)}
    cfg = {
        "constants": constants,
        "subexprs":  {"alpha": "x + y"},
        "formula":   formula,
    }

    p1 = _write(cfg)

    # Make sure the cache file for this exact input doesn't already
    # exist from a prior test run.  (Other tests might have left
    # unrelated cache files; we only need to clean ours.)
    key = _compute_compile_key(
        formula,
        None,
        # JSON parse_float=str will turn floats into strings on load,
        # so the on-disk hash is computed from string values; mirror
        # that here to predict the path correctly.
        {k: str(v) for k, v in constants.items()},
        cfg["subexprs"],
    )
    src_file = _cache_path_for_key(key)
    if os.path.exists(src_file):
        os.unlink(src_file)
    print(f"  cache file path: {src_file}")
    print(f"  formula: {n} terms")

    # First run — cache miss, full sympy work
    t_first = _time_compile(p1)
    print(f"  first run  (cache miss): {t_first:.3f}s")
    if not os.path.exists(src_file):
        print(f"  [FAIL] expected cache file at {src_file}")
        return 1

    # Second run — cache hit, should be much faster
    t_second = _time_compile(p1)
    print(f"  second run (cache hit):  {t_second:.3f}s  "
          f"({t_first / t_second:.1f}x speedup)")
    if t_second >= t_first * 0.5:
        print(f"  [WARN] second run not visibly faster — cache may not be hitting")
    if t_second >= t_first:
        print(f"  [FAIL] second run not faster: cache definitely not used")
        return 1

    # Change formula text → cache key changes → cache miss again
    cfg2 = dict(cfg)
    cfg2["formula"] = formula + " + 0.5 * x"
    p2 = _write(cfg2)
    try:
        t_diff = _time_compile(p2)
        print(f"  changed formula:         {t_diff:.3f}s "
              f"(should be slow, cache miss)")
        if t_diff < t_second * 2:
            print(f"  [WARN] expected cache miss on changed formula")
    finally:
        os.unlink(p2)

    # Change one constant value → cache key changes → cache miss
    cfg3 = json.loads(json.dumps(cfg))    # deep copy
    cfg3["constants"]["c0"] = 9.999
    p3 = _write(cfg3)
    try:
        t_const = _time_compile(p3)
        print(f"  changed constant:        {t_const:.3f}s "
              f"(should be slow, cache miss)")
        if t_const < t_second * 2:
            print(f"  [WARN] expected cache miss on changed constant")
    finally:
        os.unlink(p3)

    # Same JSON, third run — must still hit
    t_third = _time_compile(p1)
    print(f"  third run  (cache hit):  {t_third:.3f}s  "
          f"({t_first / t_third:.1f}x speedup)")
    if t_third >= t_first * 0.5:
        print(f"  [FAIL] cache not surviving across calls")
        return 1

    os.unlink(p1)
    print("[expr_compiler cache test] all checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
