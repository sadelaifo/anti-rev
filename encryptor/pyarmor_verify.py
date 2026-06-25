#!/usr/bin/env python3
"""
pyarmor_verify — verify a PyArmor-obfuscated tree behaves like the original.

PyArmor cannot be decrypted; instead you VERIFY CORRECTNESS by running the
obfuscated code (it self-decrypts in memory) and comparing its behaviour to
the plaintext original.  This tool does a differential test:

  * for each case (module, func, args, kwargs) it calls the entrypoint in the
    PLAINTEXT tree and in the OBFUSCATED tree — each in its OWN subprocess, so
    the two copies of the same module name (and the pyarmor runtime) never
    clash — and compares the result (or the raised exception).

  * with no cases file it falls back to an IMPORT SMOKE test: import every
    module under the obfuscated tree in a subprocess and report failures
    (catches a broken obfuscation / missing pyarmor_runtime / arch mismatch).

A case is "correct" when both sides return an equal value OR both raise the
same exception type+message.

Usage:
  # differential test (recommended)
  pyarmor_verify.py --plain ./src --obf ./dist/obf --cases cases.json

  # import-smoke only (no plaintext needed)
  pyarmor_verify.py --obf ./dist/obf

cases.json:
  [ {"module": "pkg.math", "func": "add", "args": [2, 3]},
    {"module": "pkg.parser", "func": "parse", "args": ["x=1"], "kwargs": {"strict": true}} ]

Notes:
  * The obfuscated tree must contain its pyarmor_runtime_xxxx package and match
    this interpreter's Python version + platform.
  * Results are serialised for comparison (JSON, else repr) — make entrypoints
    return comparable values, or wrap them in a thin adapter in the cases.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RESULT_SENTINEL = "__PYARMOR_VERIFY_RESULT__"


def _safe_serialize(value) -> str:
    try:
        return "json:" + json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return "repr:" + repr(value)


# ── worker: runs inside a subprocess with `root` on sys.path ──────────
def _worker(root: str, module: str, func: str, payload: str, outfile: str) -> int:
    rec: dict
    try:
        sys.path.insert(0, root)
        mod = importlib.import_module(module)
        fn = getattr(mod, func)
        call = json.loads(payload)
        result = fn(*call.get("args", []), **call.get("kwargs", {}))
        rec = {"ok": True, "value": _safe_serialize(result)}
    except BaseException as e:  # noqa: BLE001 — an exception IS part of behaviour
        rec = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    Path(outfile).write_text(json.dumps(rec))
    return 0


def _run_side(root: str, case: dict) -> dict:
    """Invoke this script as a worker for one (root, case); return its record."""
    payload = json.dumps({"args": case.get("args", []),
                          "kwargs": case.get("kwargs", {})})
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out = tf.name
    try:
        env = dict(os.environ)
        cmd = [sys.executable, os.path.abspath(__file__), "--worker",
               "--root", root, "--module", case["module"], "--func", case["func"],
               "--payload", payload, "--out", out]
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
        try:
            rec = json.loads(Path(out).read_text())
        except (OSError, ValueError):
            rec = {"ok": False,
                   "error": f"worker crashed (rc={p.returncode}): "
                            f"{(p.stderr or p.stdout).strip()[:300]}"}
        return rec
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


# ── import-smoke: import every module under a tree ────────────────────
def _discover_modules(root: Path) -> list[str]:
    mods = []
    for dirpath, _d, names in os.walk(root):
        for n in names:
            if not n.endswith(".py") or n.startswith("_"):
                continue
            rel = Path(dirpath, n).relative_to(root).with_suffix("")
            parts = rel.parts
            if any(p.startswith("pyarmor_runtime") for p in parts):
                continue
            mods.append(".".join(parts))
    return sorted(set(mods))


def _import_smoke(root: str) -> list[tuple[str, str]]:
    failures = []
    for mod in _discover_modules(Path(root)):
        code = ("import sys; sys.path.insert(0, %r); "
                "import importlib; importlib.import_module(%r)" % (root, mod))
        p = subprocess.run([sys.executable, "-c", code],
                           capture_output=True, text=True)
        if p.returncode != 0:
            failures.append((mod, (p.stderr or p.stdout).strip().splitlines()[-1:][0]
                             if (p.stderr or p.stdout).strip() else "import failed"))
    return failures


def main():
    ap = argparse.ArgumentParser(
        description="Verify a PyArmor-obfuscated tree behaves like the original.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # worker mode (internal)
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--root", help=argparse.SUPPRESS)
    ap.add_argument("--module", help=argparse.SUPPRESS)
    ap.add_argument("--func", help=argparse.SUPPRESS)
    ap.add_argument("--payload", help=argparse.SUPPRESS)
    ap.add_argument("--out", help=argparse.SUPPRESS)
    # user mode
    ap.add_argument("--obf", help="obfuscated tree (required in normal mode)")
    ap.add_argument("--plain", help="plaintext original tree (for differential test)")
    ap.add_argument("--cases", help="JSON cases file [{module,func,args,kwargs}]")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.worker:
        return _worker(args.root, args.module, args.func, args.payload, args.out)

    if not args.obf:
        ap.error("--obf is required")
    obf = str(Path(args.obf).resolve())

    # ── differential test ─────────────────────────────────────────────
    if args.cases:
        if not args.plain:
            ap.error("--cases requires --plain (the original tree to compare against)")
        plain = str(Path(args.plain).resolve())
        cases = json.loads(Path(args.cases).read_text())
        mism, ok = [], 0
        for c in cases:
            rp = _run_side(plain, c)
            ro = _run_side(obf, c)
            same = (rp == ro)
            label = f"{c['module']}.{c['func']}({', '.join(map(repr, c.get('args', [])))})"
            if same:
                ok += 1
                if args.verbose:
                    print(f"  PASS  {label}  -> {rp.get('value', rp.get('error'))}")
            else:
                mism.append((label, rp, ro))
                print(f"  FAIL  {label}\n        plain: {rp}\n        obf  : {ro}")
        print(f"\n[pyarmor-verify] differential: {ok}/{len(cases)} match, "
              f"{len(mism)} mismatch")
        return 1 if mism else 0

    # ── import-smoke fallback ──────────────────────────────────────────
    print(f"[pyarmor-verify] import-smoke over {obf}")
    fails = _import_smoke(obf)
    total = len(_discover_modules(Path(obf)))
    for mod, err in fails:
        print(f"  FAIL  {mod}: {err}")
    print(f"\n[pyarmor-verify] import-smoke: {total - len(fails)}/{total} imported, "
          f"{len(fails)} failed")
    if not args.plain:
        print("[pyarmor-verify] (no --cases/--plain: ran import-smoke only — "
              "add cases for a behavioural diff)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
