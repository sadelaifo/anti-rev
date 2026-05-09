#!/usr/bin/env python3
"""Runtime micro-benchmark for expr_compiler-produced functions.

Measures *call-time* cost of three paths against the same formula:

  1. numba JIT (jit=True, fastmath=True, cache=True)
  2. pure Python   (jit=False)
  3. Python's own eval() of the formula string at the same point
     — included as a sanity baseline; eval() is what people would
     reach for in absence of this module

Plus, for the small formula only, a hand-rolled Python lambda — to
show the floor (no Python function-call dispatch beyond what
numba/Python already do).

Output is *not* a pass/fail test — there's no threshold.  It's a
diagnostic so you can decide whether ``jit=True`` is worth the
~few-hundred-ms first-call LLVM compile cost for your actual call
rate.

Run from the project root::

    python3 tests/expr_compiler/bench_runtime.py
"""
from __future__ import annotations

import gc
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import make_expr_func   # noqa: E402


def time_calls(fn, args, n_calls: int, n_trials: int = 3) -> float:
    """Median of ``n_trials`` runs of ``n_calls`` invocations.
    Returns ns per call.  GC paused for the timed loop so a stray
    collection cycle doesn't skew the result."""
    # Warmup — triggers JIT compile, fills CPU caches.
    for _ in range(1000):
        fn(*args)
    times = []
    for _ in range(n_trials):
        gc.collect()
        gc.disable()
        try:
            t0 = time.perf_counter()
            for _ in range(n_calls):
                fn(*args)
            elapsed = time.perf_counter() - t0
        finally:
            gc.enable()
        times.append(elapsed / n_calls * 1e9)
    times.sort()
    return times[len(times) // 2]   # median


def fmt_ns(ns: float) -> str:
    if ns < 1000:
        return f"{ns:6.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1000:6.1f} us"
    return f"{ns / 1_000_000:6.2f} ms"


def fmt_throughput(ns: float) -> str:
    cps = 1e9 / ns
    if cps >= 1e6:
        return f"{cps / 1e6:5.1f} M/s"
    if cps >= 1e3:
        return f"{cps / 1e3:5.1f} K/s"
    return f"{cps:5.0f}/s"


def main() -> int:
    # Three formula scales — tune the term count to whatever feels
    # representative of your real workload.
    cases = [
        ("small (5 terms)",
         "a*b + c**2 + 0.5*a*b*c - 1.5e-3*a + 2.0",
         ["a", "b", "c"], (1.5, 2.5, 3.5)),

        ("medium (50 terms)",
         " + ".join(f"{(i + 1) * 1e-3} * x**{i % 4} * y**{(i + 5) % 3}"
                    for i in range(50)),
         ["x", "y"], (1.5, 2.5)),

        ("large (500 terms)",
         " + ".join(f"{(i + 1) * 1e-3} * x**{i % 4} * y**{(i + 5) % 3}"
                    for i in range(500)),
         ["x", "y"], (1.5, 2.5)),
    ]

    # Hand-rolled reference for the small formula — bypasses any
    # codegen indirection, gives a "no compile pipeline at all"
    # baseline.  Hand-rolling is impractical for medium/large.
    def hand_small(a, b, c):
        return a * b + c**2 + 0.5 * a * b * c - 1.5e-3 * a + 2.0

    print("Runtime benchmark — median of 3 trials, 1M calls each")
    print("(jit=True warms up first; first-call latency reported separately below)")
    print()
    print(f"{'formula':<22}  {'JIT':>20}  {'pure Py':>20}  "
          f"{'eval()':>20}  {'hand':>20}")
    print("-" * 110)

    jit_first_call_ms: list = []

    for label, formula, params, args in cases:
        # 1. JIT path
        try:
            t0 = time.perf_counter()
            f_jit = make_expr_func(formula, params, jit=True)
            f_jit(*args)                           # trigger JIT compile
            jit_first_call_ms.append((label,
                                       (time.perf_counter() - t0) * 1000.0))
            ns_jit = time_calls(f_jit, args, n_calls=1_000_000)
            jit_str = f"{fmt_ns(ns_jit)}  {fmt_throughput(ns_jit)}"
        except ImportError:
            jit_str = "(no numba)"
            jit_first_call_ms.append((label, None))

        # 2. Pure-Python exec'd function
        f_py = make_expr_func(formula, params, jit=False)
        ns_py = time_calls(f_py, args, n_calls=200_000)
        py_str = f"{fmt_ns(ns_py)}  {fmt_throughput(ns_py)}"

        # 3. Plain eval() of the same string
        code = compile(formula, "<bench>", "eval")
        local_ns = dict(zip(params, args))

        def eval_call():
            return eval(code, {"__builtins__": {}}, local_ns)

        ns_eval = time_calls(eval_call, (), n_calls=200_000)
        eval_str = f"{fmt_ns(ns_eval)}  {fmt_throughput(ns_eval)}"

        # 4. Hand-rolled (only for small)
        if "small" in label:
            ns_hand = time_calls(hand_small, args, n_calls=1_000_000)
            hand_str = f"{fmt_ns(ns_hand)}  {fmt_throughput(ns_hand)}"
        else:
            hand_str = "-"

        print(f"{label:<22}  {jit_str:>20}  {py_str:>20}  "
              f"{eval_str:>20}  {hand_str:>20}")

    # First-call latency table — separate because units differ.
    print()
    print("JIT first-call latency (LLVM compile + CPU cache cold):")
    for label, ms in jit_first_call_ms:
        if ms is None:
            print(f"  {label:<22}: (no numba)")
        else:
            print(f"  {label:<22}: {ms:7.0f} ms")

    print()
    print("Notes:")
    print("  * 'JIT' includes numba dispatcher overhead (~50 ns) on top of")
    print("    the compiled body. Tight inner loops in your business code")
    print("    will see numbers close to these.")
    print("  * 'pure Py' is what you get with jit=False — same generated")
    print("    code path (CSE temps + return), but no native compile.")
    print("  * 'eval()' is included as a 'what if I just did the obvious")
    print("    thing' baseline. It pays a Python parse-cache lookup +")
    print("    dict-based name resolution per call.")
    print("  * 'hand' is the floor: a Python lambda doing the arithmetic")
    print("    directly. Nothing this module produces will be faster.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
