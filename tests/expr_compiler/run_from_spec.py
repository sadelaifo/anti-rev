#!/usr/bin/env python3
"""Data-driven verification runner.

The test spec lists where to find the formula config and a series of
sample points.  Variable values and expected outputs may be:

  - literal numbers (``"v": 220.0``)
  - field references / small arithmetic over external JSON data
    sources, evaluated as Python expressions in a sandboxed namespace
    (``"v": "in.case_1.voltage + 0.5"``)

Formulas in the config may be stored as either a ``{name: formula}``
dict or as a list (keyed by stringified index — ``"0"``, ``"1"``, ...).
This handles the common case where the formula JSON is shaped as an
unnamed array of expressions.

Usage::

    python3 tests/expr_compiler/run_from_spec.py path/to/test_spec.json

Exit code is 0 on full pass, 1 on any FAIL, 2 if spec or referenced
files are missing.  Paths inside the spec are resolved relative to
the spec's directory so a relative spec can reference sibling files.
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


class _JsonAccessor:
    """Read-only wrapper around a dict/list so ``obj.key`` and
    ``obj[k]`` both work in eval'd spec expressions.  Lets users
    write ``inputs.case_1.voltage`` or ``inputs["case_1"]["voltage"]``
    interchangeably.
    """
    __slots__ = ("_data",)

    def __init__(self, data):
        object.__setattr__(self, "_data", data)

    def _wrap(self, v):
        if isinstance(v, (dict, list)):
            return _JsonAccessor(v)
        return v

    def __getattr__(self, key):
        if key.startswith("_"):
            raise AttributeError(key)
        data = object.__getattribute__(self, "_data")
        try:
            return self._wrap(data[key])
        except (KeyError, TypeError) as e:
            raise AttributeError(
                f"no field {key!r} in spec data source: {e}") from None

    def __getitem__(self, key):
        return self._wrap(self._data[key])

    def __repr__(self):
        return f"_JsonAccessor({self._data!r})"


# Sandbox allowed inside eval()'d test-spec expressions.  Math
# helpers users are likely to want — abs / min / max / pow — plus
# the math module under a short name.  No __builtins__ access, no
# imports, no file I/O.
import math as _math
_SPEC_EVAL_GLOBALS = {
    "__builtins__": {"abs": abs, "min": min, "max": max,
                     "pow": pow, "round": round},
    "math": _math,
}


def _resolve_value(v, namespace):
    """A spec value is a number (used as-is) or a string (evaluated
    as a Python expression in ``namespace``).  Returns a float."""
    if isinstance(v, bool):
        raise TypeError(f"bool is not a numeric spec value: {v!r}")
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            result = eval(v, _SPEC_EVAL_GLOBALS, namespace)
        except Exception as e:
            raise ValueError(
                f"failed to evaluate spec expression {v!r}: "
                f"{type(e).__name__}: {e}") from None
        try:
            return float(result)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"spec expression {v!r} did not produce a number "
                f"(got {type(result).__name__})") from None
    raise TypeError(
        f"spec value must be a number or expression string, "
        f"got {type(v).__name__}: {v!r}")


def _path_exists(path_expr, namespace) -> bool:
    """Cheap try-resolve used by auto_test_cases to skip data fields
    that aren't present in a given case (e.g. some cases only have
    a subset of variables or expected values)."""
    try:
        eval(path_expr, _SPEC_EVAL_GLOBALS, namespace)
        return True
    except Exception:
        return False


def _build_test_cases(spec, namespace, funcs):
    """Expand the user's ``test_cases`` list, auto-binding vars and
    expected against the per-case ``binding`` template when the
    entry names a case from the data files.

    Entry shapes accepted:

      * **String** — shorthand for ``{"case": <string>}``.  The
        listed case is looked up in the data sources and every
        function argument / formula name resolves automatically.

      * **Dict with ``case`` field** — auto-bind first, then merge
        any explicit ``vars`` / ``expected`` keys on top (so the
        user can override one or two entries).

      * **Dict without ``case`` field** — purely manual, exactly
        like before: ``vars`` and ``expected`` must be written out.

    The ``binding`` block defines the templates::

        "binding": {
          "vars_from":     "inputs.{case}",
          "expected_from": "expected.{case}"
        }

    For a case named ``"case_hot"``, the runner looks up
    ``inputs.case_hot.<arg>`` for every parameter of every function
    and ``expected.case_hot.<formula_name>`` for every compiled
    function.  Missing fields are silently dropped — that function /
    expected entry just doesn't appear (so partial coverage in the
    data files doesn't produce noisy errors).
    """
    binding = spec.get("binding", {})
    vars_template     = binding.get("vars_from")
    expected_template = binding.get("expected_from")

    # Pre-compute argument-name union and formula-name list once.
    union_args = set()
    for fn in funcs.values():
        py_fn = getattr(fn, "py_func", fn)
        n = py_fn.__code__.co_argcount
        union_args.update(py_fn.__code__.co_varnames[:n])
    union_args = sorted(union_args)
    formula_names = list(funcs.keys())

    raw = spec.get("test_cases") or spec.get("samples", [])
    out: list = []
    for i, entry in enumerate(raw):
        if isinstance(entry, str):
            entry = {"case": entry}
        elif not isinstance(entry, dict):
            raise TypeError(
                f"test_cases[{i}] must be a string or dict, "
                f"got {type(entry).__name__}")

        case_key = entry.get("case")
        explicit_vars     = entry.get("vars", {})
        explicit_expected = entry.get("expected", {})

        if case_key is not None:
            if not vars_template and not expected_template:
                raise ValueError(
                    f"test_cases[{i}] references case={case_key!r} but "
                    f"spec has no `binding.vars_from` / "
                    f"`binding.expected_from` template defined")

            auto_vars: dict = {}
            if vars_template:
                for arg in union_args:
                    path = f"{vars_template}.{arg}".format(case=case_key)
                    if _path_exists(path, namespace):
                        auto_vars[arg] = path

            auto_expected: dict = {}
            if expected_template:
                for name in formula_names:
                    path = f"{expected_template}.{name}".format(case=case_key)
                    if _path_exists(path, namespace):
                        auto_expected[name] = path

            # Explicit entries override auto-bound paths for the same key.
            merged_vars     = {**auto_vars,     **explicit_vars}
            merged_expected = {**auto_expected, **explicit_expected}

            label = entry.get("label") or case_key
            out.append({
                "label":    label,
                "vars":     merged_vars,
                "expected": merged_expected,
            })
        else:
            label = entry.get("label", "<unlabeled>")
            out.append({
                "label":    label,
                "vars":     explicit_vars,
                "expected": explicit_expected,
            })
    return out


def _resolve_constants(cfg, path_spec):
    if path_spec is None:
        return None
    if isinstance(path_spec, list):
        merged = {}
        for p in path_spec:
            chunk = get_at_path(cfg, p)
            overlap = set(merged) & set(chunk)
            if overlap:
                raise ValueError(
                    f"constants name(s) {sorted(overlap)} appear in "
                    f"multiple paths within constants_at")
            merged.update(chunk)
        return merged
    return get_at_path(cfg, path_spec)


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

    # ---- load external data sources --------------------------------
    namespace = {}
    for src_name, rel_path in spec.get("data_sources", {}).items():
        src_path = (spec_path.parent / rel_path).resolve()
        if not src_path.exists():
            print(f"data source {src_name!r} not found: {src_path}",
                  file=sys.stderr)
            return 2
        with src_path.open(encoding="utf-8") as fh:
            namespace[src_name] = _JsonAccessor(json.load(fh))

    print(f"test spec:      {spec_path}")
    print(f"formula config: {config_path}")
    if namespace:
        for k, _ in namespace.items():
            print(f"data source:    {k} = "
                  f"{(spec_path.parent / spec['data_sources'][k]).resolve()}")
    print(f"tolerance:      {tolerance:.0e}")
    print()

    # ---- compile + build references --------------------------------
    print(f"[1/3] compiling formulas (jit={compile_opts.get('jit', True)}) ...")
    funcs = make_expr_funcs_from_json(
        str(config_path),
        exprs_at     = exprs_at,
        constants_at = constants_at,
        subexprs_at  = subexprs_at,
        **compile_opts,
    )
    print(f"      {len(funcs)} function(s) ready: "
          f"{sorted(funcs)}")

    print(f"[2/3] building sympy references ...")
    with config_path.open(encoding="utf-8") as fh:
        cfg = json.load(fh, parse_float=str)
    raw_exprs = get_at_path(cfg, exprs_at)
    if isinstance(raw_exprs, list):
        exprs_dict = {str(i): v for i, v in enumerate(raw_exprs)}
    else:
        exprs_dict = raw_exprs
    constants  = _resolve_constants(cfg, constants_at)
    subexprs   = get_at_path(cfg, subexprs_at) if subexprs_at else None

    references = {}
    for name in funcs:
        references[name] = make_reference_func(
            exprs_dict[name],
            constants = constants,
            subexprs  = subexprs,
        )
    print(f"      {len(references)} reference(s) ready")

    # Expand test_cases (handles strings, auto-bind dicts, manual dicts)
    cases = _build_test_cases(spec, namespace, funcs)

    print(f"[3/3] running {len(cases)} test case(s) ...")
    print()

    n_ok = n_fail = n_skip = 0

    for case in cases:
        label = case.get("label", "<unlabeled>")
        raw_vars = case["vars"]
        raw_expected = case.get("expected", {})

        # Resolve every var (literal or expression) into a float.
        try:
            vars_dict = {k: _resolve_value(v, namespace)
                         for k, v in raw_vars.items()}
        except (ValueError, TypeError) as e:
            print(f"=== {label} ===")
            print(f"  [ERR ] resolving vars: {e}")
            n_fail += 1
            print()
            continue

        # Same for expected — but resolve lazily, per-formula, so a
        # bad reference doesn't sink the whole case.
        var_str = ", ".join(f"{k}={v}" for k, v in vars_dict.items())
        print(f"=== {label} ===")
        print(f"sample: {var_str}")

        for name, fn in funcs.items():
            py_fn = getattr(fn, "py_func", fn)
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
            if name in raw_expected:
                try:
                    expected = _resolve_value(raw_expected[name], namespace)
                except (ValueError, TypeError) as e:
                    expected_str = f"  expected RESOLVE-ERR ({e})"
                    expected_ok = False
                else:
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
          f"(of {total} checks across {len(cases)} test case(s))")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
