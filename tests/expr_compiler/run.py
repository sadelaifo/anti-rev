#!/usr/bin/env python3
"""Local smoke test for tools/expr_compiler.make_expr_func_from_json.

Loads ./config.json, inlines named sub-expressions, bakes numeric
constants in as literals, auto-detects the surviving free symbols
as positional parameters, and verifies the compiled callable agrees
with a hand-computed reference.

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
    _substitute_constants,
    _expand_subexprs,
)

HERE = Path(__file__).parent
CFG = HERE / "config.json"

# Constants from config.json — duplicated here so the reference function
# is independent of the loader under test.
K1, K2, BIAS, SCALE = 6.5e-5, 0.001, 12, 0.5


def reference(i: float, v: float) -> float:
    """Hand-computed reference, mirrors the JSON formula:

        power = v * i
        ohm   = K1 * v**2
        iron  = K2 * i**2
        loss  = ohm + iron
        f     = SCALE*power - loss + BIAS
    """
    return SCALE * v * i - (K1 * v**2 + K2 * i**2) + BIAS


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def main() -> int:
    print(f"[expr_compiler test] config: {CFG}")

    f_py = make_expr_func_from_json(
        CFG,
        expr_at      = "formula",
        constants_at = "constants",
        subexprs_at  = "subexprs",
        jit          = False,
        debug        = True,
    )

    py_argnames = list(f_py.__code__.co_varnames[:f_py.__code__.co_argcount])
    print(f"  auto-detected param order: {py_argnames}")
    # Constants k1/k2/bias/scale are baked in; only v and i survive,
    # alphabetical sort gives [i, v].
    assert py_argnames == ["i", "v"], py_argnames

    samples = [
        (1.5,  220.0),
        (1.0,    1.0),
        (0.0,   10.0),
        (4.0,   -3.0),
    ]
    print("  pure-Python results:")
    for (i_val, v_val) in samples:
        got = f_py(i_val, v_val)
        ref = reference(i_val, v_val)
        ok  = near(got, ref)
        marker = "OK" if ok else "FAIL"
        print(f"    f(i={i_val}, v={v_val}) = {got:>14.6g}    "
              f"ref = {ref:>14.6g}    [{marker}]")
        if not ok:
            return 1

    # JIT path — only if numba is around.
    try:
        f_jit = make_expr_func_from_json(
            CFG,
            expr_at      = "formula",
            constants_at = "constants",
            subexprs_at  = "subexprs",
            jit          = True,
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

    # Helpers spot-check.
    inlined = _substitute_constants(
        "scale * power - loss + bias",
        {"scale": 0.5, "bias": 12},
    )
    print(f"  constants substituted into 'scale*power - loss + bias': {inlined}")

    chained = _expand_subexprs(
        "scale*power - loss + bias",
        {"power": "v*i", "ohm": "k1*v**2", "iron": "k2*i**2",
         "loss":  "ohm + iron"},
    )
    print(f"  subexprs inlined (chain loss -> ohm + iron): {chained}")

    other = get_at_path({"a": [{"b": 42}]}, "a[0].b")
    assert other == 42, other
    print(f"  get_at_path('a[0].b') = {other}")

    print("[expr_compiler test] all checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
