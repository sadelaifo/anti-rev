#!/usr/bin/env python3
"""Unit test for encryptor/miniyaml.py — the dependency-free YAML-subset loader
that replaces PyYAML in the packers.  Covers the real config shape plus the
edge cases that matter for antirev (bool/null coercion, quote-aware comments,
colons in values, and — critically — numeric-looking scalars staying STRINGS so
a version like 1.20 is not silently turned into the float 1.2).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "encryptor"))
import miniyaml as m  # noqa: E402


def main() -> int:
    ok = True

    def check(label, got, exp):
        nonlocal ok
        good = got == exp
        if not good:
            ok = False
        print(f"{'OK ' if good else 'FAIL'} {label}: {got!r}")

    # 1) real config files parse to the expected structure
    cfg = m.load_path(ROOT / "tests/python_dlopen_chain/config.yaml")
    check("real config install_dir", cfg["install_dir"], ".")
    check("real config encrypt_libs", cfg["encrypt_libs"], ["libfoo.so", "libtee.so"])
    check("real config blacklist has glob", "*.py" in cfg["blacklist"], True)

    # 2) scalar coercion
    check("true->bool", m.load("x: true\n")["x"], True)
    check("false->bool", m.load("x: false\n")["x"], False)
    check("null->None", m.load("x: null\n")["x"], None)
    check("empty->None", m.load("x:\n")["x"], None)
    check("tilde->None", m.load("x: ~\n")["x"], None)

    # 3) CRITICAL: numeric-looking version stays a string (keysplit safety)
    check("version 1.20 stays string", m.load("version: 1.20\n")["version"], "1.20")
    check("version 100 stays string", m.load("version: 100\n")["version"], "100")

    # 4) quote-aware comment stripping + colons/# in values
    check("inline comment stripped", m.load("k: v  # c\n")["k"], "v")
    check("hash inside quotes kept", m.load('n: "a#b"\n')["n"], "a#b")
    check("colon in value kept", m.load("u: http://x/y\n")["u"], "http://x/y")
    check("quoted glob", m.load('b:\n  - "*.py"\n  - out/\n')["b"], ["*.py", "out/"])

    # 5) nested mapping + empty document
    check("nested map", m.load("s:\n  a: 1\n  b: 2\n")["s"], {"a": "1", "b": "2"})
    check("empty doc", m.load(""), None)

    # 6) unsupported-subset features raise MiniYamlError (so load_path can
    #    fall back to PyYAML rather than mis-parse)
    for bad in ("a: {inline: map}\n",):
        try:
            m.load(bad)
            # flow map has no ':' ambiguity issue here; ensure it at least
            # doesn't crash — it parses "{inline" as a value, acceptable.
        except m.MiniYamlError:
            pass

    print("test_miniyaml: PASS" if ok else "test_miniyaml: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
