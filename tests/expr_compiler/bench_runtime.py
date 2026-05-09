#!/usr/bin/env python3
"""Time each compiled function in a JSON config.

Loads ``CONFIG_PATH`` via :func:`make_expr_funcs_from_json`, walks
the resulting ``{name: callable}`` dict, runs ``N_CALLS`` invocations
of every function whose parameters are all in ``SAMPLE``, prints
ns/call and throughput.

Adapt: change CONFIG_PATH and the four ``*_AT`` paths to wherever
your formulas / constants / subexprs live, set SAMPLE to a realistic
operating point, set JIT to True if numba is available.

Run from the project root::

    python3 tests/expr_compiler/bench_runtime.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import make_expr_funcs_from_json   # noqa: E402


# -----------------------------------------------------------------
# Adapt these to your own config.
# -----------------------------------------------------------------

CONFIG_PATH    = "config.json"
EXPRS_PATH     = "expr"               # path to the {name: formula} dict
CONSTANTS_PATH = "constants"          # or a list of paths, or None
SUBEXPRS_PATH  = "subexprs"           # or None

SAMPLE = {"v": 220.0, "i": 1.5, "t": 25.0}

JIT     = False     # set True after `pip install numba`
N_CALLS = 1_000_000


# -----------------------------------------------------------------
# Driver — usually no need to edit below this line.
# -----------------------------------------------------------------

def main() -> int:
    cfg_path = Path(CONFIG_PATH)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        print("this script is a template — point CONFIG_PATH at your JSON",
              file=sys.stderr)
        return 2

    print(f"compiling {cfg_path} (jit={JIT}) ...")
    t0 = time.perf_counter()
    funcs = make_expr_funcs_from_json(
        str(cfg_path),
        exprs_at     = EXPRS_PATH,
        constants_at = CONSTANTS_PATH,
        subexprs_at  = SUBEXPRS_PATH,
        jit          = JIT,
    )
    print(f"  {len(funcs)} functions compiled in {time.perf_counter() - t0:.2f}s")
    print(f"  sample: {SAMPLE}")
    print()

    print(f"{'name':<24}  {'args':<24}  {'ns/call':>10}  "
          f"{'throughput':>12}")
    print("-" * 76)

    for name, fn in funcs.items():
        py_fn = getattr(fn, 'py_func', fn)
        n = py_fn.__code__.co_argcount
        arg_names = list(py_fn.__code__.co_varnames[:n])

        missing = [a for a in arg_names if a not in SAMPLE]
        if missing:
            print(f"{name:<24}  {','.join(arg_names):<24}  "
                  f"{'SKIP':>10}  missing {missing}")
            continue

        call_args = tuple(SAMPLE[a] for a in arg_names)

        # warmup — triggers numba JIT compile, fills CPU caches
        for _ in range(1000):
            fn(*call_args)

        t0 = time.perf_counter()
        for _ in range(N_CALLS):
            fn(*call_args)
        elapsed = time.perf_counter() - t0

        ns = elapsed * 1e9 / N_CALLS
        cps = N_CALLS / elapsed
        thru = (f"{cps / 1e6:5.2f} M/s" if cps >= 1e6
                else f"{cps / 1e3:5.1f} K/s")
        print(f"{name:<24}  {','.join(arg_names):<24}  {ns:>9.1f}   {thru:>12}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
