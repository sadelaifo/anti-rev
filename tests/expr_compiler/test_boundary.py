#!/usr/bin/env python3
"""Boundary-sampling demo for tools/expr_compiler.

Sets up an engineering-style JSON config (transformer-ish: power,
iron loss, copper loss, efficiency, temperature correction), then
runs the compiled functions through a series of boundary sample
points — zero values, very small / very large magnitudes, negative
inputs, edge temperatures.

Three layers of cross-check at every sample point:

  1.  ``verify(funcs, formulas, sample, ...)`` — confirms each
      compiled function agrees with sympy's own substitution result.
      Catches bugs in CSE / pycode / exec / numba.

  2.  Hand-rolled Python reference implementation — confirms the
      sympy parse path interpreted the formula the way the author
      intended.  Catches operator-precedence / operator-typo bugs in
      the JSON itself (sympy parses ``a*b + c`` and ``a*(b+c)``
      differently; without an independent reference, verify() would
      pass either one).

  3.  Spot-check against a known business value where applicable.

If any layer disagrees the test exits non-zero with the offending
sample + formula named.

Run from the project root::

    python3 tests/expr_compiler/test_boundary.py
"""
from __future__ import annotations

import json
import math
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    clear_compile_cache,
    describe,
    make_expr_funcs_from_json,
    reference_value,
    verify,
)


# Constants — must match cfg["constants"] below; duplicated here so
# the hand-rolled reference functions don't depend on the loader.
K1, K2, SCALE, ALPHA, T_REF = 6.5e-5, 0.001, 0.5, 0.004, 25.0


# ---- hand-rolled reference implementations ---------------------
# Independent Python code for every formula in cfg["exprs"]. If a
# user typos `*` as `+` in the JSON, sympy still parses cleanly and
# verify() (which goes through sympy too) would not catch it. This
# layer does.
def hand_power(v, i, t):
    return SCALE * v * i


def hand_loss(v, i, t):
    return K1 * v**2 + K2 * i**2


def hand_efficiency(v, i, t):
    p = v * i
    iron = K1 * v**2
    copper = K2 * i**2
    return p / (p + iron + copper + 1e-12)


def hand_t_corr(v, i, t):
    return 1.0 + ALPHA * (t - T_REF)


HAND = {
    "f_power":      hand_power,
    "f_loss":       hand_loss,
    "f_efficiency": hand_efficiency,
    "f_t_corr":     hand_t_corr,
}


def near(a: float, b: float, eps: float = 1e-9) -> bool:
    if math.isnan(a) and math.isnan(b):
        return True
    if math.isinf(a) and math.isinf(b) and (a > 0) == (b > 0):
        return True
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def main() -> int:
    # Realistic transformer-style formula set.
    cfg = {
        "constants": {
            "k1":    K1,
            "k2":    K2,
            "scale": SCALE,
            "alpha": ALPHA,
            "T_ref": T_REF,
        },
        "subexprs": {
            "power":  "v * i",
            "iron":   "k1 * v**2",
            "copper": "k2 * i**2",
        },
        "exprs": {
            "f_power":      "scale * power",
            "f_loss":       "iron + copper",
            # 1e-12 in denom avoids 0/0 when both v and i are 0.
            "f_efficiency": "power / (power + iron + copper + 1e-12)",
            "f_t_corr":     "1 + alpha * (t - T_ref)",
        },
    }

    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)

    # Force a clean compile so this test exercises the real pipeline,
    # not yesterday's cached source.
    clear_compile_cache()

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

    print("--- compiled functions ---")
    describe(funcs)
    print()

    # ---- boundary samples -----------------------------------------
    # Each tuple is (label, sample_dict).  Labels are descriptive so
    # a failure tells you immediately which condition broke.
    samples = [
        # Nominal — 220 V, 1.5 A, room temp.  Sanity baseline.
        ("nominal operating point",
         {"v": 220.0, "i":  1.5, "t":  25.0}),

        # Zero current — power and copper loss both vanish; iron
        # loss survives.  Efficiency should be ~0 (no useful work).
        ("zero current",
         {"v": 220.0, "i":  0.0, "t":  25.0}),

        # Zero voltage — everything proportional to v drops to zero.
        # Iron loss, power, copper loss all 0.  Efficiency: 0/0
        # masked by 1e-12 → very small.
        ("zero voltage",
         {"v":   0.0, "i":  1.5, "t":  25.0}),

        # Both zero — exactly the 0/0 boundary on efficiency.  The
        # 1e-12 offset in the denom makes the result well-defined.
        ("both v and i zero",
         {"v":   0.0, "i":  0.0, "t":  25.0}),

        # Tiny magnitudes — check that nothing underflows
        # catastrophically.  IEEE-754 double can hold ~1e-300.
        ("very small (1e-9)",
         {"v": 1e-9,  "i": 1e-9, "t":  25.0}),

        # Large magnitudes — `v**2` for v=1e6 is 1e12, well below
        # double's 1e308 ceiling.  Should be fine.
        ("very large (1e6 / 1e3)",
         {"v": 1e6,   "i": 1e3,  "t":  25.0}),

        # Cold extreme — t_corr should drop below 1.
        ("cold temperature (-40 °C)",
         {"v": 220.0, "i":  1.5, "t": -40.0}),

        # Hot extreme — t_corr should rise above 1.
        ("hot temperature (+85 °C)",
         {"v": 220.0, "i":  1.5, "t":  85.0}),

        # Negative voltage — physics-wise this represents reverse-
        # polarity AC.  power and copper unchanged structure, iron
        # loss stays positive (v² is even).
        ("negative voltage",
         {"v": -220.0, "i":  1.5, "t":  25.0}),

        # Negative current with negative voltage — power is positive
        # (negatives cancel), iron / copper unchanged.
        ("both v and i negative",
         {"v": -220.0, "i": -1.5, "t":  25.0}),
    ]

    # ---- run all samples through three layers ---------------------
    failures = 0
    for label, sample in samples:
        print(f"=== {label} ===")
        sample_str = ", ".join(f"{k}={v}" for k, v in sample.items())
        print(f"sample: {sample_str}")

        # Layer 1+2: verify() compares compiled vs sympy reference
        records = verify(
            funcs, cfg["exprs"], sample,
            constants = cfg["constants"],
            subexprs  = cfg["subexprs"],
        )

        # Layer 3: cross-check compiled against hand-rolled Python
        for rec in records:
            name = rec['name']
            if not rec.get('ok'):
                failures += 1
                continue
            hand_val = HAND[name](**sample)
            compiled = rec['compiled']
            if not near(hand_val, compiled, eps=1e-9):
                rel = (abs(hand_val - compiled)
                       / (abs(hand_val) + abs(compiled) + 1e-300))
                print(f"  [HAND-MISMATCH] {name}: "
                      f"hand={hand_val}  compiled={compiled}  "
                      f"rel_err={rel:.2e}")
                failures += 1
            else:
                print(f"  [HAND-OK ] {name}: hand={hand_val:.6g} "
                      f"matches compiled")
        print()

    # ---- spot-check one known business value ---------------------
    print("=== spot-check known value ===")
    # Hand-derived: f_power(220, 1.5) = 0.5 * 220 * 1.5 = 165.0
    sample = {"v": 220.0, "i": 1.5, "t": 25.0}
    expected = 165.0
    got = funcs["f_power"](sample["i"], sample["v"])
    print(f"  f_power(i=1.5, v=220) = {got}  (expected {expected})")
    if not near(got, expected, eps=1e-12):
        print(f"  [FAIL] off-by-{got - expected}")
        failures += 1
    else:
        print(f"  [OK  ] business-known value matches")

    # Also verify reference_value standalone matches.
    ref = reference_value(
        cfg["exprs"]["f_power"], sample,
        constants=cfg["constants"], subexprs=cfg["subexprs"],
    )
    print(f"  reference_value(...) = {ref}")
    if not near(ref, expected, eps=1e-12):
        print(f"  [FAIL] sympy reference disagrees too")
        failures += 1
    print()

    n_total = len(samples) * len(funcs) + 2  # +2 for spot-checks above
    print(f"[expr_compiler boundary test] "
          f"{n_total - failures} / {n_total} checks passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
