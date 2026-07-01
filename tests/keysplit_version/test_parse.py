#!/usr/bin/env python3
"""test_parse.py — unit test for the Python keysplit version-field parser.

Guards encryptor/protect.py:parse_version_field() (the canonical Python mirror
of stub.c ksv_parse) and the config-literal == runtime-parse consistency the
whole keysplit contract depends on.  No cryptography dependency: we import only
the pure parser, falling back to executing the source if the module import
pulls in unavailable deps.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_parser():
    """Return parse_version_field from protect.py.  Prefer a normal import
    (Linux CI has `cryptography`); if that pulls in an unavailable dep, fall
    back to exec-ing only the pure function block from the source."""
    sys.path.insert(0, str(ROOT / "encryptor"))
    try:
        import importlib
        return importlib.import_module("protect").parse_version_field
    except (Exception, SystemExit):
        # protect.py sys.exit()s at import if `cryptography` is absent
        src = (ROOT / "encryptor" / "protect.py").read_text(encoding="utf-8")
        ns = {"sys": sys}
        start = src.index("def parse_version_field")
        end = src.index("\ndef derive_real_key")
        block = "_VERSION_MARKER = b\"Version: \"\n_VERSION_SPC = b\"SPC\"\n" \
                + src[start:end]
        exec(block, ns)
        return ns["parse_version_field"]


def main() -> int:
    pv = _load_parser()

    cases = [
        (b"Version: V100R001C00SPC010\n",              b"V100R001C00"),
        (b"prod\nVersion: 1.2.3 SPC b05 foo\nother\n", b"1.2.3"),
        (b"Version: 1.2.3 build 2024\n",               b"1.2.3 build 2024"),
        (b"Version:    V1   \n",                       b"V1"),
        (b"Version: V100R001C00SPC010",                b"V100R001C00"),
    ]
    ok = True
    for inp, exp in cases:
        try:
            got = pv(inp)
        except SystemExit:
            got = None
        status = "OK " if got == exp else "FAIL"
        if got != exp:
            ok = False
        print(f"{status} {inp!r:45} -> {got!r}")

    # config-literal (verbatim) must equal what the runtime script parses to
    literal = "V100R001C00".strip().encode()
    parsed = pv(b"Version: V100R001C00SPC010\n")
    if literal != parsed:
        ok = False
        print(f"FAIL consistency: literal {literal!r} != parsed {parsed!r}")
    else:
        print("OK  config-literal == runtime-parse")

    for bad in (b"no marker here\n", b"Version: SPC123\n", b"Version:   \n"):
        try:
            pv(bad)
            ok = False
            print(f"FAIL should reject {bad!r}")
        except SystemExit:
            print(f"OK  reject {bad!r}")

    print("keysplit_version_py: PASS" if ok else "keysplit_version_py: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
