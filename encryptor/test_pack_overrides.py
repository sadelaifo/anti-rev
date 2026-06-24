#!/usr/bin/env python3
"""Tests for antirev-pack.py CLI-over-config field precedence + version/lrxd.

Covers:
  1. _resolve_field unit precedence: CLI > config.yaml > default.
  2. End-to-end: --version / --lrxd / --output-dir override config.yaml,
     the daemon binary is named from the merged 'lrxd', and the pack
     manifest records the merged version.

Run:  python encryptor/test_pack_overrides.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE / "antirev-pack.py"


def _load_pack_module():
    """Import the hyphen-named module via spec_from_file_location.

    Register in sys.modules BEFORE exec_module (standard pattern; also what
    PyArmor-obfuscated modules require — see issue #846).
    """
    spec = importlib.util.spec_from_file_location("antirev_pack", PACK)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["antirev_pack"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_resolve_field_precedence():
    m = _load_pack_module()
    rf = m._resolve_field
    cfg = {"k": "from_config"}
    # CLI wins over config
    assert rf("from_cli", cfg, "k", "def") == "from_cli"
    # config wins over default when no CLI
    assert rf(None, cfg, "k", "def") == "from_config"
    # default when neither CLI nor config
    assert rf(None, {}, "k", "def") == "def"
    # None default when absent everywhere
    assert rf(None, {}, "k") is None
    # empty-string CLI is still an explicit override (not None)
    assert rf("", cfg, "k", "def") == ""
    print("ok: _resolve_field precedence (CLI > config > default)")


def _make_dummy_stub(path: Path):
    # A minimal ET_DYN x86_64 ELF header is enough for classify_elf; but the
    # packer also tolerates a non-ELF stub (falls back to both arches). Use a
    # tiny non-ELF file to keep the test self-contained and arch-neutral.
    path.write_bytes(b"not-an-elf-stub\n")


def test_end_to_end_overrides():
    m = _load_pack_module()  # ensures imports resolve before subprocess run
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        install = td / "install"
        (install / "etc").mkdir(parents=True)
        # one plaintext data file so there is something to copy; no ELFs so the
        # run needs no readelf/toolchain and stays platform-neutral.
        (install / "etc" / "app.conf").write_text("hello\n")
        stub = td / "stub.bin"
        _make_dummy_stub(stub)

        cfg = td / "config.yaml"
        cfg.write_text(
            "install_dir: {}\n".format(install.as_posix())
            + "output_dir: {}\n".format((td / "out_CONFIG").as_posix())
            + "stub: {}\n".format(stub.as_posix())
            + "key: prod.key\n"
            + "lrxd: lrxd_config\n"
            + "version: 0.0-config\n"
            + "libs: encrypt\n"
            + "copy:\n  - etc/\n"
        )

        out_cli = td / "out_CLI"
        r = subprocess.run(
            [sys.executable, str(PACK), "--config", str(cfg),
             "--output-dir", str(out_cli),
             "--lrxd", "lrxd_cli",
             "--version", "9.9-cli"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, "packer failed:\n" + r.stdout + r.stderr

        # CLI --output-dir overrode config output_dir
        assert out_cli.exists(), "CLI --output-dir was not used"
        assert not (td / "out_CONFIG").exists(), "config output_dir should be overridden"
        # copied data file landed in the CLI output tree
        assert (out_cli / "etc" / "app.conf").read_text() == "hello\n"

        # manifest written next to the config (NOT inside the shipped output)
        man = td / "antirev-pack-manifest.json"
        assert man.exists(), "manifest not written next to config"
        assert not (out_cli / "antirev-pack-manifest.json").exists(), \
            "manifest must not be inside output_dir (fingerprint)"
        data = json.loads(man.read_text())
        # CLI version/lrxd won over the config values
        assert data["version"] == "9.9-cli", data
        assert data["lrxd"] == "lrxd_cli", data
        print("ok: end-to-end CLI overrides config (output_dir/version/lrxd); "
              "manifest outside output tree")


if __name__ == "__main__":
    test_resolve_field_precedence()
    test_end_to_end_overrides()
    print("\nALL PASS")
