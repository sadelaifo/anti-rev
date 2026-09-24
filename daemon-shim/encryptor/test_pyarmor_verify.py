#!/usr/bin/env python3
"""Tests for pyarmor_verify.py's comparison logic (no PyArmor needed).

We can't install PyArmor here, but the verifier's job is a behavioural diff
between two trees. We validate that with plaintext trees:
  * identical trees           -> all cases match (exit 0)
  * behaviour-changed tree    -> mismatch detected (exit 1)
  * exception parity          -> both raising the same error counts as match
  * import-smoke              -> a module that fails to import is reported

Run:  python encryptor/test_pyarmor_verify.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VERIFY = HERE / "pyarmor_verify.py"

GOOD = "def add(a, b):\n    return a + b\n\n" \
       "def need_positive(x):\n    if x < 0:\n        raise ValueError('negative')\n    return x * 2\n"
BAD = "def add(a, b):\n    return a + b + 1  # wrong!\n\n" \
      "def need_positive(x):\n    if x < 0:\n        raise ValueError('negative')\n    return x * 2\n"


def _mktree(base: Path, name: str, mathx_src: str) -> Path:
    root = base / name
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("")
    (root / "pkg" / "mathx.py").write_text(mathx_src)
    return root


def _run(plain, obf, cases):
    cmd = [sys.executable, str(VERIFY), "--plain", str(plain), "--obf", str(obf),
           "--cases", str(cases)]
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    with tempfile.TemporaryDirectory() as t:
        td = Path(t)
        plain = _mktree(td, "plain", GOOD)
        obf_good = _mktree(td, "obf_good", GOOD)
        obf_bad = _mktree(td, "obf_bad", BAD)

        cases = td / "cases.json"
        cases.write_text(json.dumps([
            {"module": "pkg.mathx", "func": "add", "args": [2, 3]},
            {"module": "pkg.mathx", "func": "need_positive", "args": [-1]},  # both raise
            {"module": "pkg.mathx", "func": "need_positive", "args": [5]},
        ]))

        # identical -> all match, exit 0
        r = _run(plain, obf_good, cases)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "3/3 match" in r.stdout, r.stdout
        print("ok: identical trees -> all cases match (incl. exception parity)")

        # behaviour change in add() -> 1 mismatch, exit 1
        r = _run(plain, obf_bad, cases)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 mismatch" in r.stdout, r.stdout
        assert "pkg.mathx.add(2, 3)" in r.stdout
        print("ok: behaviour-changed tree -> mismatch detected (exit 1)")

        # import-smoke: a module that raises at import is reported
        broken = td / "broken"
        (broken / "pkg").mkdir(parents=True)
        (broken / "pkg" / "__init__.py").write_text("")
        (broken / "pkg" / "good.py").write_text("X = 1\n")
        (broken / "pkg" / "bad.py").write_text("raise RuntimeError('boom at import')\n")
        r = subprocess.run([sys.executable, str(VERIFY), "--obf", str(broken)],
                           capture_output=True, text=True)
        assert r.returncode == 1, r.stdout + r.stderr
        assert "pkg.bad" in r.stdout and "1 failed" in r.stdout, r.stdout
        print("ok: import-smoke reports a module that fails to import")

    print("\nALL PASS")


if __name__ == "__main__":
    main()
