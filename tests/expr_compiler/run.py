#!/usr/bin/env python3
"""Local smoke test for tools/expr_compiler.make_expr_func_from_json.

Loads ./config.json, compiles the main expression with parameters
gathered from two separate keys and named sub-expressions inlined,
then verifies the JIT and pure-Python paths agree with a hand-computed
reference value.

Run from the project root::

    python3 tests/expr_compiler/run.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (        # noqa: E402
    get_at_path,
    make_expr_func_from_json,
    _expand_subexprs,
)

HERE = Path(__file__).parent
CFG = HERE / "config.json"


def reference(v, i, k1, k2):
    """Hand-computed reference, mirrors the JSON formula:

        scaled = 0.5 * (v*i)
        loss   = k1*v**2 + k2*i**2
        main   = scaled - loss
    """
    return 0.5 * v * i - (k1 * v**2 + k2 * i**2)


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def main() -> int:
    print(f"[expr_compiler test] config: {CFG}")

    # Pure-Python path first — fastest to fail with a clear traceback if
    # the JSON shape is wrong.
    f_py = make_expr_func_from_json(
        CFG,
        expr_at     = "main",
        params_at   = ["inputs", "constants"],
        subexprs_at = "subexprs",
        jit         = False,
    )

    py_argnames = list(f_py.__code__.co_varnames[:f_py.__code__.co_argcount])
    print(f"  param order (auto-built): {py_argnames}")
    assert py_argnames == ["v", "i", "k1", "k2"], py_argnames

    samples = [
        (220.0, 1.5, 1.2e-5, 3.0e-5),
        (1.0,   1.0, 1.0,    1.0),
        (10.0,  0.0, 0.5,    0.5),
        (-3.0,  4.0, 0.1,    0.2),
    ]
    print("  pure-Python results:")
    for args in samples:
        got = f_py(*args)
        ref = reference(*args)
        ok  = near(got, ref)
        marker = "OK" if ok else "FAIL"
        print(f"    f{args} = {got:>14.6g}    ref = {ref:>14.6g}    [{marker}]")
        if not ok:
            return 1

    # JIT path — only if numba is around.
    try:
        f_jit = make_expr_func_from_json(
            CFG,
            expr_at     = "main",
            params_at   = ["inputs", "constants"],
            subexprs_at = "subexprs",
            jit         = True,
        )
    except ImportError:
        print("  numba not installed — skipping JIT cross-check")
    else:
        f_jit(*samples[0])  # warm up
        for args in samples:
            got = f_jit(*args)
            ref = reference(*args)
            if not near(got, ref):
                print(f"  JIT mismatch at {args}: {got} vs {ref}")
                return 1
        print("  JIT path matches reference on all samples")

    # Spot-check the helpers used internally.
    inlined = _expand_subexprs("scaled - loss", {
        "power":  "v*i",
        "ohm":    "k1*v**2",
        "iron":   "k2*i**2",
        "loss":   "ohm + iron",
        "scaled": "0.5*power",
    })
    print(f"  inlined formula: {inlined}")

    other = get_at_path({"a": [{"b": 42}]}, "a[0].b")
    assert other == 42, other
    print(f"  get_at_path('a[0].b') = {other}")

    print("[expr_compiler test] all checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
