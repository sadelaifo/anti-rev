#!/usr/bin/env python3
"""Run sample-driven verification from a JSON test specification.

The test spec lists where to find the formula config, which compile
options to use, and a series of named sample points (each with the
variable values and, optionally, business-known expected outputs).
The script compiles all formulas, builds independent sympy
references, and reports PASS/FAIL/SKIP per (sample, formula).

Usage::

    python3 tests/expr_compiler/run_from_spec.py path/to/test_spec.json

A minimal test spec::

    {
      "formula_config": {
        "path":         "config.json",
        "exprs_at":     "expr",
        "constants_at": "constants",
        "subexprs_at":  "subexprs"
      },
      "compile_options": { "jit": false },
      "tolerance": 1e-9,
      "samples": [
        { "label": "nominal",
          "vars":  {"v": 220.0, "i": 1.5} },
        { "label": "zero current",
          "vars":     {"v": 220.0, "i": 0.0},
          "expected": {"f_power": 0.0, "f_loss": 3.146} }
      ]
    }

Exit code is 0 on full pass, 1 on any FAIL.  Paths inside
``formula_config.path`` are resolved relative to the test spec's
directory (so a relative spec can reference a sibling config).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from expr_compiler import (              # noqa: E402
    get_at_path,
    make_expr_funcs_from_json,
    make_reference_func,
)


def _resolve_path(d, path):
    """Single-path lookup — same syntax as get_at_path."""
    return get_at_path(d, path)


def _resolve_constants(cfg, path_spec):
    """`path_spec` may be a single path or a list of paths; merge
    all dicts at those paths into one.  Mirrors the multi-path
    `constants_at` handling in make_expr_funcs_from_json."""
    if path_spec is None:
        return None
    if isinstance(path_spec, list):
        merged = {}
        for p in path_spec:
            chunk = _resolve_path(cfg, p)
            overlap = set(merged) & set(chunk)
            if overlap:
                raise ValueError(
                    f"constants name(s) {sorted(overlap)} appear in "
                    f"multiple paths within constants_at")
            merged.update(chunk)
        return merged
    return _resolve_path(cfg, path_spec)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: run_from_spec.py <test_spec.json>", file=sys.stderr)
        return 2

    spec_path = Path(sys.argv[1]).resolve()
    if not spec_path.exists():
        print(f"test spec not found: {spec_path}", file=sys.stderr)
        return 2

    with spec_path.open(encoding="utf-8") as fh:
        spec = json.load(fh)

    fc = spec["formula_config"]
    config_path = (spec_path.parent / fc["path"]).resolve()
    if not config_path.exists():
        print(f"formula config not found: {config_path}", file=sys.stderr)
        return 2

    exprs_at     = fc["exprs_at"]
    constants_at = fc.get("constants_at")
    subexprs_at  = fc.get("subexprs_at")

    compile_opts = spec.get("compile_options", {})
    tolerance    = spec.get("tolerance", 1e-9)
    samples      = spec.get("samples", [])

    print(f"test spec:      {spec_path}")
    print(f"formula config: {config_path}")
    print(f"tolerance:      {tolerance:.0e}")
    print(f"samples:        {len(samples)}")
    print()

    print(f"[1/3] compiling formulas (jit={compile_opts.get('jit', True)}) ...")
    funcs = make_expr_funcs_from_json(
        str(config_path),
        exprs_at     = exprs_at,
        constants_at = constants_at,
        subexprs_at  = subexprs_at,
        **compile_opts,
    )
    print(f"      {len(funcs)} function(s) ready")

    print(f"[2/3] building sympy references ...")
    with config_path.open(encoding="utf-8") as fh:
        cfg = json.load(fh, parse_float=str)
    exprs_dict = _resolve_path(cfg, exprs_at)
    constants  = _resolve_constants(cfg, constants_at)
    subexprs   = _resolve_path(cfg, subexprs_at) if subexprs_at else None

    references = {}
    for name in funcs:
        references[name] = make_reference_func(
            exprs_dict[name],
            constants = constants,
            subexprs  = subexprs,
        )
    print(f"      {len(references)} reference(s) ready")

    print(f"[3/3] running {len(samples)} sample(s) ...")
    print()

    n_ok = n_fail = n_skip = 0

    for sample in samples:
        label = sample.get("label", "<unlabeled>")
        vars_dict = sample["vars"]
        expected_dict = sample.get("expected", {})

        var_str = ", ".join(f"{k}={v}" for k, v in vars_dict.items())
        print(f"=== {label} ===")
        print(f"sample: {var_str}")

        for name, fn in funcs.items():
            py_fn = getattr(fn, 'py_func', fn)
            n_args = py_fn.__code__.co_argcount
            args = list(py_fn.__code__.co_varnames[:n_args])

            missing = [a for a in args if a not in vars_dict]
            if missing:
                print(f"  [SKIP] {name:<20} vars missing {missing}")
                n_skip += 1
                continue

            call_args = [vars_dict[a] for a in args]

            try:
                got = float(fn(*call_args))
            except Exception as e:
                print(f"  [ERR ] {name:<20} compiled call failed: "
                      f"{type(e).__name__}: {e}")
                n_fail += 1
                continue

            try:
                ref = float(references[name](vars_dict))
            except Exception as e:
                print(f"  [ERR ] {name:<20} reference failed: "
                      f"{type(e).__name__}: {e}")
                n_fail += 1
                continue

            rel = abs(got - ref) / (abs(ref) + 1e-300)
            ref_ok = rel < tolerance

            expected_str = ""
            expected_ok = True
            if name in expected_dict:
                expected = float(expected_dict[name])
                exp_rel = abs(got - expected) / (abs(expected) + 1e-300)
                expected_ok = exp_rel < tolerance
                exp_mark = "OK" if expected_ok else "FAIL"
                expected_str = (f"  expected={expected:.6g} "
                                f"({exp_mark} rel={exp_rel:.1e})")

            ok = ref_ok and expected_ok
            status = "OK  " if ok else "FAIL"
            print(f"  [{status}] {name:<20} ref={ref:>12.6g}  "
                  f"got={got:>12.6g}  rel={rel:.1e}{expected_str}")

            if ok:
                n_ok += 1
            else:
                n_fail += 1
        print()

    total = n_ok + n_fail + n_skip
    print(f"Summary: {n_ok} OK / {n_fail} FAIL / {n_skip} SKIP "
          f"(of {total} checks across {len(samples)} sample(s))")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
