#!/usr/bin/env python3
"""Test for tools/expr_compiler.make_expr_funcs_from_json — compile
several formulas from one JSON file in a single call, with shared
constants + subexprs.

Run from the project root::

    python3 tests/expr_compiler/test_multi.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import make_expr_funcs_from_json     # noqa: E402


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def main() -> int:
    cfg = {
        "constants": {
            "k1":   6.5e-5,
            "k2":   0.001,
            "bias": 12,
            "scale": 0.5,
        },
        "subexprs": {
            "power": "v * i",
            "loss":  "k1*v**2 + k2*i**2",
        },
        "exprs": {
            "f_power_balance":   "scale*power - loss + bias",
            "f_pure_loss":       "loss",
            "f_quad_power":      "power**2 + 1",
            # Different parameter set on purpose — uses t and p:
            "f_other_vars":      "k1*t + k2*p**2",
            # No variables at all — pure constant after substitution:
            "f_just_constants":  "scale*bias - k1",
        },
    }
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w") as fh:
        json.dump(cfg, fh)

    try:
        funcs = make_expr_funcs_from_json(
            p,
            exprs_at     = "exprs",
            constants_at = "constants",
            subexprs_at  = "subexprs",
            jit          = False,
        )
    finally:
        os.unlink(p)

    expected_names = set(cfg["exprs"])
    if set(funcs) != expected_names:
        print(f"  [FAIL] returned keys {set(funcs)} != expected {expected_names}")
        return 1
    print(f"  [OK]   returned {len(funcs)} compiled functions: {sorted(funcs)}")

    # Each formula gets its own auto-detected parameter set
    def argnames(fn):
        n = fn.__code__.co_argcount
        return list(fn.__code__.co_varnames[:n])

    expected_args = {
        "f_power_balance":  ["i", "v"],     # auto-detect, alphabetical
        "f_pure_loss":      ["i", "v"],
        "f_quad_power":     ["i", "v"],
        "f_other_vars":     ["p", "t"],
        "f_just_constants": [],
    }
    for name, want in expected_args.items():
        got = argnames(funcs[name])
        if got != want:
            print(f"  [FAIL] {name} args {got} != expected {want}")
            return 1
    print(f"  [OK]   per-formula auto-detected param order is independent")

    # Numerical correctness against hand-rolled references
    K1, K2, BIAS, SCALE = 6.5e-5, 0.001, 12, 0.5
    cases = [
        ("f_power_balance",
         (1.5, 220.0),
         lambda i, v: SCALE * v * i - (K1 * v**2 + K2 * i**2) + BIAS),
        ("f_pure_loss",
         (3.0, 100.0),
         lambda i, v: K1 * v**2 + K2 * i**2),
        ("f_quad_power",
         (2.0, 50.0),
         lambda i, v: (v * i)**2 + 1),
        ("f_other_vars",
         (4.0, 9.0),
         lambda p, t: K1 * t + K2 * p**2),
        ("f_just_constants",
         (),
         lambda: SCALE * BIAS - K1),
    ]
    for name, args, ref in cases:
        got = funcs[name](*args)
        want = ref(*args)
        if not near(float(got), float(want)):
            print(f"  [FAIL] {name}{args}: got {got}, want {want}")
            return 1
        print(f"  [OK]   {name}{args} = {got}")

    # params_at override applies a uniform call signature across all formulas
    cfg_with_order = {
        "constants": {"k": 0.001},
        "exprs": {
            "g1": "k*x + y",
            "g2": "x*x - y",
            "g3": "x",                         # only uses x
        },
        "var_order": ["x", "y"],
    }
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w") as fh:
        json.dump(cfg_with_order, fh)
    try:
        gs = make_expr_funcs_from_json(
            p,
            exprs_at     = "exprs",
            constants_at = "constants",
            params_at    = "var_order",
            jit          = False,
        )
    finally:
        os.unlink(p)

    for name in ("g1", "g2", "g3"):
        if argnames(gs[name]) != ["x", "y"]:
            print(f"  [FAIL] {name} signature should be (x, y), got "
                  f"{argnames(gs[name])}")
            return 1
        # g3 should accept y as unused arg
    if not near(gs["g3"](7.0, 999.0), 7.0):
        print(f"  [FAIL] g3(7, 999) = {gs['g3'](7.0, 999.0)}, expected 7.0")
        return 1
    print(f"  [OK]   params_at override gives all formulas the same signature")

    # Wrong shape at exprs_at should fail loudly
    cfg_bad = {"exprs": {"f1": ["not", "a", "string"]}}
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w") as fh:
        json.dump(cfg_bad, fh)
    try:
        try:
            make_expr_funcs_from_json(p, exprs_at="exprs", jit=False)
        except TypeError as e:
            print(f"  [OK]   non-string formula caught: {e}")
        else:
            print(f"  [FAIL] non-string formula not rejected")
            return 1
    finally:
        os.unlink(p)

    print("[expr_compiler multi test] all checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
