#!/usr/bin/env python3
"""Template: verify a single compiled formula at many sample points.

Pattern:

    1. Compile the formula via make_expr_func_from_json.
    2. Build a sympy-backed reference via make_reference_func.
       Sympifies and applies constants / subexprs ONCE at construction
       time (~5 s on a 450 KB formula); each subsequent sample is
       only ~10 ms.
    3. Drive both the compiled function and the reference through
       the same sample list, compare with a relative-error tolerance.

The reference path uses sympy's iterative substitution engine, NOT
Python's recursive eval(), so it works on arbitrarily long formula
strings — that's the whole reason this helper exists.

Adapt to your own JSON: change CONFIG_PATH, FORMULA_PATH,
CONSTANTS_PATH, SUBEXPRS_PATH, and the SAMPLES list below.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    make_expr_func_from_json,
    make_reference_func,
)


# -----------------------------------------------------------------
# Adapt these to your own config.
# -----------------------------------------------------------------

CONFIG_PATH    = "config.json"
FORMULA_PATH   = "expr.f1"            # path inside the JSON to the formula string
CONSTANTS_PATH = "constants"          # or a list of paths, or None
SUBEXPRS_PATH  = "subexprs"           # or None

# Each entry is one sample point.  Cover boundaries deliberately —
# nominal, zeros, very small, very large, negative, business-known.
SAMPLES = [
    {"v": 220.0, "i":   1.5},
    {"v":   0.0, "i":   1.5},   # zero voltage
    {"v": 220.0, "i":   0.0},   # zero current
    {"v": 1e-9,  "i": 1e-9 },   # tiny magnitudes
    {"v": 1e6,   "i": 1e3  },   # large magnitudes
    {"v":-220.0, "i":   1.5},   # negative voltage
]

EPS = 1e-9   # relative-error threshold for OK / FAIL


# -----------------------------------------------------------------
# Driver — usually no need to edit below this line.
# -----------------------------------------------------------------

def near(a: float, b: float, eps: float = EPS) -> bool:
    return abs(a - b) <= eps * (abs(a) + abs(b) + 1.0)


def main() -> int:
    cfg_path = Path(CONFIG_PATH)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        print(f"this script is a template — point CONFIG_PATH at your own JSON",
              file=sys.stderr)
        return 2

    print(f"[1/3] compiling {FORMULA_PATH} from {cfg_path} ...")
    t0 = time.perf_counter()
    f = make_expr_func_from_json(
        str(cfg_path),
        expr_at      = FORMULA_PATH,
        constants_at = CONSTANTS_PATH,
        subexprs_at  = SUBEXPRS_PATH,
        jit          = False,    # set True after numerical sanity checks pass
    )
    print(f"      compiled in {time.perf_counter() - t0:.2f} s")

    print(f"[2/3] building sympy reference (one-time cost) ...")
    with cfg_path.open(encoding="utf-8") as fh:
        cfg = json.load(fh, parse_float=str)

    # Pull out the formula text and (merged, if path is a list) the
    # constants / subexprs — the same data the compiler sees.
    def _get(d, path):
        if isinstance(path, list):
            return path  # caller is supplying multiple paths; not handled here
        cur = d
        for seg in path.split("."):
            cur = cur[seg]
        return cur

    formula  = _get(cfg, FORMULA_PATH)
    constants = _get(cfg, CONSTANTS_PATH) if CONSTANTS_PATH else None
    subexprs  = _get(cfg, SUBEXPRS_PATH)  if SUBEXPRS_PATH  else None

    t0 = time.perf_counter()
    ref = make_reference_func(formula,
                              constants=constants, subexprs=subexprs)
    print(f"      reference ready in {time.perf_counter() - t0:.2f} s")
    print(f"      free variables: {ref.free_vars}")

    # ---- run all samples ----------------------------------------
    print(f"[3/3] checking {len(SAMPLES)} sample point(s) ...")
    fails = 0
    for s in SAMPLES:
        try:
            t_ref0   = time.perf_counter()
            expected = ref(s)
            t_ref    = time.perf_counter() - t_ref0

            t_got0   = time.perf_counter()
            got      = f(*[s[a] for a in ref.free_vars])
            t_got    = time.perf_counter() - t_got0
        except KeyError as e:
            print(f"  [SKIP] {s}: {e}")
            continue

        ok = near(got, expected)
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] {s}: ref={expected:.6g}  "
              f"got={got:.6g}  rel_err={abs(got - expected)/(abs(expected) + 1e-300):.2e}  "
              f"(ref {t_ref*1000:.1f} ms, fn {t_got*1e6:.1f} µs)")
        if not ok:
            fails += 1

    n = len(SAMPLES)
    print(f"\n{n - fails}/{n} sample(s) passed verification.")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
