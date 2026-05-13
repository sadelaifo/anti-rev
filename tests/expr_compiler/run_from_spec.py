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
import re
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


def _expand_container_paths(template_list, case_key, namespace, label):
    """For ``vars_from`` / ``expected_from`` given as a list of
    container paths: resolve each template, fetch the container
    (must be a dict), and return ``{field_name: full_field_path}``
    for every top-level key.  Several containers can be merged —
    later entries override earlier ones on key collision.

    Used when the user's data is shaped::

        file1.<case>.a = {var1: ..., var2: ...}    # group dict #1
        file2.<case>.b = {var3: ..., var4: ...}    # group dict #2

    and the spec lists::

        "vars_from": [
          "file1.{case}.a",
          "file2.{case}.b"
        ]

    so the runner pulls every key from every container and exposes
    them all as vars (or expected, depending on `label`).
    """
    out: dict = {}
    for tmpl in template_list:
        if not isinstance(tmpl, str):
            raise TypeError(
                f"binding.{label}[*] in list-of-containers form must be a "
                f"template string, got {type(tmpl).__name__}")
        container_path = tmpl.format(case=case_key)
        try:
            container = eval(container_path, _SPEC_EVAL_GLOBALS, namespace)
        except Exception:
            # Path missing for this case — skip the container.
            continue
        if isinstance(container, _JsonAccessor):
            raw = container._data
        else:
            raw = container
        if not isinstance(raw, dict):
            raise ValueError(
                f"binding.{label} container {container_path!r} must "
                f"point to a dict, got {type(raw).__name__}")
        for field_name in raw:
            if field_name.startswith("_"):
                continue   # skip _comment-style metadata
            out[field_name] = f"{container_path}.{field_name}"
    return out


def _build_auto_vars(vars_from, union_args, case_key, namespace):
    """Resolve the per-variable auto-binding for one case.

    ``vars_from`` accepts three forms — pick whichever matches how
    your data is organised:

      * **String** ``"inputs.{case}"`` — runner builds a path per
        parameter as ``<template>.<argname>``, replacing ``{case}``.
        Use when all variables share one source and field names
        match parameter names::

            vars_from = "inputs.{case}"
            # v ← inputs.<case>.v,  i ← inputs.<case>.i, ...

      * **Dict** ``{argname: template}`` — each parameter has its
        own template, free to reference different sources and
        different sub-paths.  Use when variables are scattered or
        field names disagree with parameter names::

            vars_from = {
              "v": "file1.{case}.a",       # v ← field a in file1
              "i": "file2.{case}.x"        # i ← field x in file2
            }

      * **List of container paths** — each entry resolves to a dict;
        the runner enumerates its keys and exposes each one as a
        var.  Use when the data is grouped into sub-dicts that bundle
        several variables::

            # file1.err.a = {var1: ..., var2: ...}
            # file2.err.b = {var3: ..., var4: ...}
            vars_from = ["file1.{case}.a", "file2.{case}.b"]
            # vars = {var1, var2, var3, var4}
    """
    auto: dict = {}
    if isinstance(vars_from, str):
        for arg in union_args:
            path = f"{vars_from}.{arg}".format(case=case_key)
            if _path_exists(path, namespace):
                auto[arg] = path
    elif isinstance(vars_from, list):
        auto = _expand_container_paths(vars_from, case_key, namespace,
                                       label="vars_from")
    elif isinstance(vars_from, dict):
        for arg_name, template in vars_from.items():
            if not isinstance(template, str):
                raise TypeError(
                    f"binding.vars_from[{arg_name!r}] must be a "
                    f"template string, got {type(template).__name__}")
            path = template.format(case=case_key)
            if _path_exists(path, namespace):
                auto[arg_name] = path
    else:
        raise TypeError(
            f"binding.vars_from must be string / list / dict, "
            f"got {type(vars_from).__name__}")
    return auto


_PATH_TOKEN_RE = re.compile(r'[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+')


def _build_auto_expected(expected_from, formula_names, case_key, namespace):
    """Same forms as :func:`_build_auto_vars` for expected outputs,
    plus one extra:

      * **Path template** (no operators) — e.g. ``"ref.{case}"``.
        Runner appends ``.<formula_name>`` to the end, then evaluates
        as a path lookup.  Same as before.

      * **Expression template** (contains ``+ - * / ( )``) — e.g.
        ``"a.b.c - a.d.e"``.  Each multi-segment path token in the
        expression gets ``.<formula_name>`` appended; the result is
        an arithmetic expression that's evaluated as a number.  So
        for formula ``f1`` the expression becomes
        ``"a.b.c.f1 - a.d.e.f1"`` and evaluates to the difference
        of the two per-formula fields.

        Use this when the expected value is a small computation
        over fields keyed by formula name.
    """
    auto: dict = {}
    if isinstance(expected_from, str):
        template = expected_from.format(case=case_key)
        # Detect arithmetic expression vs plain path: presence of any
        # operator means treat as expression and per-token expand.
        has_op = any(op in template for op in "+-*/()")
        if has_op:
            for name in formula_names:
                expr = _PATH_TOKEN_RE.sub(
                    lambda m: f"{m.group(0)}.{name}", template)
                if _path_exists(expr, namespace):
                    auto[name] = expr
        else:
            for name in formula_names:
                path = f"{template}.{name}"
                if _path_exists(path, namespace):
                    auto[name] = path
    elif isinstance(expected_from, list):
        auto = _expand_container_paths(expected_from, case_key, namespace,
                                       label="expected_from")
    elif isinstance(expected_from, dict):
        for name, template in expected_from.items():
            if not isinstance(template, str):
                raise TypeError(
                    f"binding.expected_from[{name!r}] must be a "
                    f"template string, got {type(template).__name__}")
            path = template.format(case=case_key)
            if _path_exists(path, namespace):
                auto[name] = path
    else:
        raise TypeError(
            f"binding.expected_from must be string / list / dict, "
            f"got {type(expected_from).__name__}")
    return auto


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

    The ``binding`` block defines the templates — either single-
    string form (all vars share a path prefix) or per-key dict form
    (each var / formula has its own template).  See
    :func:`_build_auto_vars` for the per-variable form.
    """
    binding = spec.get("binding", {})
    vars_from     = binding.get("vars_from")
    expected_from = binding.get("expected_from")

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
        # Per-case override: when the data is shaped such that paths
        # can't be expressed as a global `{case}` template (each case
        # has its own unique path components), the test_case entry
        # writes the container paths directly.  Takes precedence over
        # the global `binding`.
        per_case_vars_from     = entry.get("vars_from")
        per_case_expected_from = entry.get("expected_from")
        explicit_vars     = entry.get("vars", {})
        explicit_expected = entry.get("expected", {})

        # Resolve which binding to use for this entry:
        # per-case override > global binding (only if case_key set) > none
        if per_case_vars_from is not None:
            active_vars_from = per_case_vars_from
        elif case_key is not None:
            active_vars_from = vars_from   # may be None
        else:
            active_vars_from = None

        if per_case_expected_from is not None:
            active_expected_from = per_case_expected_from
        elif case_key is not None:
            active_expected_from = expected_from   # may be None
        else:
            active_expected_from = None

        # {case} substitution in templates uses case_key, or empty
        # string if the user wrote fully literal paths.
        subst_key = case_key if case_key is not None else ""

        auto_vars = (_build_auto_vars(active_vars_from, union_args,
                                       subst_key, namespace)
                     if active_vars_from is not None else {})
        auto_expected = (_build_auto_expected(active_expected_from,
                                               formula_names, subst_key,
                                               namespace)
                          if active_expected_from is not None else {})

        # Explicit hard-coded entries (literal values or path strings
        # in `vars` / `expected`) override the auto-bound ones.
        merged_vars     = {**auto_vars,     **explicit_vars}
        merged_expected = {**auto_expected, **explicit_expected}

        label = entry.get("label") or case_key or "<unlabeled>"
        out.append({
            "label":    label,
            "vars":     merged_vars,
            "expected": merged_expected,
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
    if len(sys.argv) == 1:
        # No argument — look for `test_spec.json` in the current working
        # directory.  Convenient default so `python3 run_from_spec.py`
        # just works when run from a directory that contains its own
        # spec file.
        spec_path = Path("test_spec.json").resolve()
    elif len(sys.argv) == 2:
        spec_path = Path(sys.argv[1]).resolve()
    else:
        print("usage: run_from_spec.py [<test_spec.json>]", file=sys.stderr)
        print("       (default spec path: ./test_spec.json)", file=sys.stderr)
        return 2

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
    # compute_ref: if False, skip the (slow) sympy reference path —
    # only the got-vs-expected layer runs.  Set in spec when running
    # large batches where sympy build per formula dominates runtime.
    compute_ref  = spec.get("compute_ref", True)
    # loose_tolerance: relative threshold used only for FAIL
    # classification — anything within this distance is still a FAIL,
    # but tagged "NEAR" / "SIGN~" so the user can separate
    # close-but-not-exact mismatches from outright magnitude errors.
    # Default 1e-2 surfaces small-formula-difference cases (truncated
    # series, hardcoded constant like 3.14159 vs sp.pi, float32
    # round-trip, etc.).
    loose_tolerance = spec.get("loose_tolerance", 1e-2)

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

    references: dict = {}
    if compute_ref:
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

        for name in funcs:
            references[name] = make_reference_func(
                exprs_dict[name],
                constants = constants,
                subexprs  = subexprs,
            )
        print(f"      {len(references)} reference(s) ready")
    else:
        print(f"[2/3] sympy references skipped (compute_ref=false in spec)")

    # Expand test_cases (handles strings, auto-bind dicts, manual dicts)
    cases = _build_test_cases(spec, namespace, funcs)

    print(f"[3/3] running {len(cases)} test case(s) ...")
    print()

    n_ok = n_fail = n_skip = 0
    # FAIL classification buckets — populated when expected fails.
    # SIGN: got ≈ -expected within tolerance (exact flip)
    # SIGN~: got ≈ -expected within loose_tolerance (flip + small drift)
    # NEAR: got ≈ +expected within loose_tolerance (close-but-not-exact)
    # DIFF: genuine magnitude mismatch (none of the above)
    fail_buckets: dict[str, list[str]] = {
        "SIGN": [], "SIGN~": [], "NEAR": [], "DIFF": []}

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

            # Layer 1: ref-vs-got (sympy reference, optional).
            ref = None
            ref_ok = True   # don't fail on missing ref
            rel = None
            if compute_ref and name in references:
                try:
                    ref = float(references[name](vars_dict))
                except Exception as e:
                    print(f"  [ERR ] {name:<20} reference failed: "
                          f"{type(e).__name__}: {e}")
                    n_fail += 1
                    continue
                rel = abs(got - ref) / (abs(ref) + 1e-300)
                ref_ok = rel < tolerance

            # Layer 2: expected-vs-got (business-known value, optional).
            expected_str = ""
            expected_ok = True
            if name in raw_expected:
                raw_expr = raw_expected[name]
                try:
                    expected = _resolve_value(raw_expr, namespace)
                except (ValueError, TypeError) as e:
                    expected_str = (f"  expected RESOLVE-ERR ({e})"
                                    f"  [from: {raw_expr}]")
                    expected_ok = False
                else:
                    denom = abs(expected) + 1e-300
                    exp_rel  = abs(got - expected) / denom
                    flip_rel = abs(got + expected) / denom
                    expected_ok = exp_rel < tolerance
                    # Classify FAIL: SIGN (exact flip) > SIGN~ (flip+drift)
                    # > NEAR (close-but-not-exact) > DIFF (real mismatch).
                    if expected_ok:
                        exp_mark = "OK"
                    elif flip_rel < tolerance:
                        exp_mark = "SIGN"
                    elif flip_rel < loose_tolerance:
                        exp_mark = "SIGN~"
                    elif exp_rel < loose_tolerance:
                        exp_mark = "NEAR"
                    else:
                        exp_mark = "DIFF"
                    expected_str = (f"  expected={expected:.6g} "
                                    f"({exp_mark} rel={exp_rel:.1e})")
                    # On FAIL, surface the source expression and bucket
                    # the failure so the summary can show the breakdown.
                    if not expected_ok:
                        if isinstance(raw_expr, str):
                            expected_str += f"  [from: {raw_expr}]"
                        fail_buckets[exp_mark].append(f"{label}/{name}")

            ok = ref_ok and expected_ok
            status = "OK  " if ok else "FAIL"
            if ref is not None:
                print(f"  [{status}] {name:<20} ref={ref:>12.6g}  "
                      f"got={got:>12.6g}  rel={rel:.1e}{expected_str}")
            else:
                print(f"  [{status}] {name:<20} "
                      f"got={got:>12.6g}{expected_str}")

            if ok:
                n_ok += 1
            else:
                n_fail += 1
        print()

    total = n_ok + n_fail + n_skip
    print(f"Summary: {n_ok} OK / {n_fail} FAIL / {n_skip} SKIP "
          f"(of {total} checks across {len(cases)} test case(s))")
    # FAIL breakdown by category.  When `got == ref` already verifies
    # the compile pipeline, the remaining buckets point at *what kind*
    # of mismatch the expected data has — sign convention, formula-form
    # drift (e.g. truncated series, hardcoded constant), or outright
    # wrong path / wrong formula.
    bucket_total = sum(len(v) for v in fail_buckets.values())
    if bucket_total:
        print()
        print(f"FAIL breakdown (loose_tolerance={loose_tolerance:.0e}):")
        print(f"  SIGN  {len(fail_buckets['SIGN']):>4}  "
              f"got ≈ -expected (exact)        — formula or expected sign flipped")
        print(f"  SIGN~ {len(fail_buckets['SIGN~']):>4}  "
              f"got ≈ -expected (within loose) — sign flip + small drift")
        print(f"  NEAR  {len(fail_buckets['NEAR']):>4}  "
              f"close but not exact            — formula-form drift "
              f"(truncated series / hardcoded constant / float32 round-trip)")
        print(f"  DIFF  {len(fail_buckets['DIFF']):>4}  "
              f"genuine magnitude mismatch     — wrong formula or wrong path")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
