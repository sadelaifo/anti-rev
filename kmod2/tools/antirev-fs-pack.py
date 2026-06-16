#!/usr/bin/env python3
# antirev-fs-pack.py — config-driven packer for the antirevfs (kmod2) design.
#
# Unlike encryptor/antirev-pack.py (which builds the stub + daemon + shim
# artifacts), this tool produces the *ciphertext lower tree* that antirevfs
# mounts over: it walks an install tree, encrypts every ELF (shared libraries
# AND executables, detected by ELF magic, not by extension) into a mirrored
# `.enc/` tree using the same `protect.py encrypt-lib` container format
# ([magic ANTREV01][iv:12][tag:16][ct...]), and leaves everything else alone.
#
# Usage:
#   antirev-fs-pack.py <config.yaml> [-j N] [--dry-run]
#
# Config (YAML):
#   install_dir: /root/proj          # tree to scan (required)
#   output_dir:  /root/proj/.enc     # mirrored ciphertext tree (required)
#   key:         proj.key.hex        # hex keyfile, relative to the config file;
#                                    #   created (0600) on first run if absent
#   blacklist:                       # optional — ELFs to leave UNencrypted
#     - libprotobuf.so*              #   (third-party libs that coexist plaintext)
#     - libdopra.so
#     - third_party/                 #   trailing '/' = path prefix
#   mirror_plaintext: true           # optional, default true — see below
#
# mirror_plaintext (default true): produce a COMPLETE mixed-content tree.  ELFs
# are encrypted; every other regular file (configs, .py, .pyc, .sh, .txt, .json,
# resources) AND blacklisted (intentionally-plaintext third-party) ELFs are
# mirrored VERBATIM (plaintext) into the tree, and symlinks are re-created.  So
# a real install dir (lib/, bin/ with mixed content) appears in full under the
# mount.  Mount it with `antirev-mount --passdata` so the module serves every
# non-ANTREV01 file as plaintext passthrough (read-only); encrypted ELFs are
# still decrypted + gated.  Because the mount is read-only, any file the app
# WRITES at runtime (e.g. python-generated .txt, __pycache__) must be redirected
# to a writable path outside the mount — antirevfs hosts only shipped content.
#
# Set mirror_plaintext: false for a minimal pure-secret tree: only encrypted
# ELFs + symlinks land in the tree; data files and blacklisted ELFs are omitted
# (they then will NOT appear under the mount — point it at pure-ELF subtrees).
#
# Symlinks are re-created verbatim in the mirror so SONAME version chains
# (libfoo.so -> libfoo.so.1 -> libfoo.so.1.2.3) keep resolving through the mount.
from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import json
import os
import sys
import time
from pathlib import Path

# Reuse protect.py's exact crypto so the container format stays in lockstep
# with what the kernel module's read_folio decrypts.
_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
sys.path.insert(0, str(_REPO / "encryptor"))
try:
    from protect import make_container, load_or_create_key  # noqa: E402
except ImportError as e:
    sys.exit(f"[error] cannot import encryptor/protect.py ({e}); "
             f"expected at {_REPO / 'encryptor' / 'protect.py'}")

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

ELF_MAGIC = b"\x7fELF"


def is_elf(path: Path) -> bool:
    """True iff the file begins with the ELF magic (covers .so and exes)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def blacklisted(rel: str, patterns: list[str]) -> bool:
    """rel is a POSIX-style path relative to install_dir.

    A pattern ending in '/' matches a path prefix (a subtree); otherwise it is
    a glob matched against the basename (e.g. 'libfoo.so*').
    """
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        if pat.endswith("/"):
            if rel == pat.rstrip("/") or rel.startswith(pat):
                return True
        elif fnmatch.fnmatch(name, pat):
            return True
    return False


def encrypt_one(src: Path, dst: Path, key: bytes) -> int:
    """Encrypt src -> dst (ANTREV01 container with embedded-key trailer).

    antirevfs has no mount-time key, so each file carries its own AES key in a
    trailer (MAGIC + iv + tag + ct + key + MAGIC); the module reads it at
    decrypt time.  Returns plaintext byte count.
    """
    data = src.read_bytes()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(make_container(data, key, embed_key=True))
    try:
        dst.chmod(src.stat().st_mode & 0o777)
    except OSError:
        pass
    return len(data)


def copy_verbatim(src: Path, dst: Path) -> int:
    """Mirror src -> dst byte-for-byte (plaintext). Returns byte count.

    Used for non-ELF data files and blacklisted (intentionally-plaintext) ELFs
    so a complete mixed-content read-only tree appears under the mount.  The
    module serves these via the `passdata` mount option (any non-ANTREV01 file
    is plaintext passthrough); they carry no ANTREV01 magic so they are never
    decrypted or gated.
    """
    data = src.read_bytes()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    try:
        dst.chmod(src.stat().st_mode & 0o777)
    except OSError:
        pass
    return len(data)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="antirevfs (kmod2) config-driven ciphertext-tree packer")
    ap.add_argument("config", help="YAML config file")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="parallel workers (default: CPU count)")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify and report, but write nothing")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"[error] config not found: {cfg_path}")
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f) or {}

    for field in ("install_dir", "output_dir"):
        if field not in cfg:
            sys.exit(f"[error] missing required field '{field}' in config")

    def _expand(p: str) -> str:
        return os.path.expanduser(os.path.expandvars(p))

    install_dir = Path(_expand(cfg["install_dir"])).resolve()
    output_dir = Path(_expand(cfg["output_dir"])).resolve()
    key_path = (cfg_path.parent / _expand(cfg.get("key", "antirev.key"))).resolve()
    patterns = [p.replace("\\", "/") for p in (cfg.get("blacklist") or [])]
    # mirror_plaintext (default True): copy non-ELF data files and blacklisted
    # ELFs verbatim into the tree so a complete mixed-content read-only dir
    # (lib/, bin/ with .py/.sh/.txt/.json + third-party plaintext libs) is fully
    # visible under the mount (mount with `passdata`).  Set False for a minimal
    # pure-secret tree (only encrypted ELFs + symlinks appear under the mount).
    mirror_plaintext = bool(cfg.get("mirror_plaintext", True))
    workers = args.jobs if args.jobs > 0 else (os.cpu_count() or 4)

    if not install_dir.is_dir():
        sys.exit(f"[error] install_dir not a directory: {install_dir}")
    if install_dir == output_dir:
        sys.exit("[error] output_dir must differ from install_dir")

    key = load_or_create_key(key_path) if not args.dry_run else b"\0" * 32

    enc_jobs: list[tuple[Path, Path]] = []
    copy_jobs: list[tuple[Path, Path]] = []
    skipped_blacklist: list[str] = []
    skipped_nonelf: list[str] = []
    symlinks: list[str] = []

    # Walk install_dir; prune output_dir if it is nested inside it so we never
    # try to re-encrypt our own ciphertext.
    for dirpath, dirnames, filenames in os.walk(install_dir, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames
                       if (dp / d).resolve() != output_dir]
        for fn in filenames:
            src = dp / fn
            rel = src.relative_to(install_dir).as_posix()
            dst = output_dir / rel

            if src.is_symlink():
                symlinks.append(rel)
                if not args.dry_run:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    if dst.is_symlink() or dst.exists():
                        dst.unlink()
                    os.symlink(os.readlink(src), dst)
                continue
            if blacklisted(rel, patterns):
                # intentionally plaintext (third-party libs that coexist): mirror
                # verbatim so they stay loadable through the mount, or drop them
                # from the tree entirely when not mirroring.
                if mirror_plaintext:
                    copy_jobs.append((src, dst))
                else:
                    skipped_blacklist.append(rel)
                continue
            if is_elf(src):
                enc_jobs.append((src, dst))
            elif mirror_plaintext:
                copy_jobs.append((src, dst))
            else:
                skipped_nonelf.append(rel)

    total_in = 0
    if not args.dry_run and enc_jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(encrypt_one, s, d, key): s for s, d in enc_jobs}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    total_in += fut.result()
                except Exception as e:  # noqa: BLE001
                    sys.exit(f"[error] encrypting {futs[fut]}: {e}")

    if not args.dry_run and copy_jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(copy_verbatim, s, d): s for s, d in copy_jobs}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    fut.result()
                except Exception as e:  # noqa: BLE001
                    sys.exit(f"[error] mirroring {futs[fut]}: {e}")

    # ── manifest (written OUTSIDE the .enc tree so it is not under the mount) ──
    manifest = {
        "install_dir": str(install_dir),
        "output_dir": str(output_dir),
        "encrypted": sorted(s.relative_to(install_dir).as_posix()
                            for s, _ in enc_jobs),
        "plaintext": sorted(s.relative_to(install_dir).as_posix()
                            for s, _ in copy_jobs),
        "symlinks": sorted(symlinks),
        "skipped_blacklist": sorted(skipped_blacklist),
        "skipped_nonelf": sorted(skipped_nonelf),
    }
    man_path = (cfg_path.parent / "antirev-fs-manifest.json").resolve()
    if not args.dry_run:
        man_path.write_text(json.dumps(manifest, indent=2) + "\n")

    # ── summary ──
    tag = "[dry-run] would encrypt" if args.dry_run else "[fs-pack] encrypted"
    print(f"{tag}: {len(enc_jobs)} ELF(s)"
          + ("" if args.dry_run else f"  ({total_in:,} plaintext bytes)"))
    print(f"          symlinks mirrored: {len(symlinks)}")
    if mirror_plaintext:
        print(f"          plaintext mirrored (data + blacklisted ELF, IN tree): "
              f"{len(copy_jobs)}")
    else:
        print(f"          blacklisted (left plaintext, NOT in tree): "
              f"{len(skipped_blacklist)}")
        print(f"          non-ELF (untouched, NOT in tree): "
              f"{len(skipped_nonelf)}")
    if not args.dry_run:
        print(f"          manifest: {man_path}")

    if mirror_plaintext and copy_jobs:
        print("  NOTE: plaintext files are mirrored into the tree — mount with "
              "`passdata`\n        so non-ANTREV01 files are served as plaintext "
              "passthrough (read-only).")
    if not mirror_plaintext and (skipped_nonelf or skipped_blacklist):
        print("  NOTE: untouched / blacklisted files do NOT appear under the "
              "antirevfs mount.\n        Set mirror_plaintext: true, or surface "
              "data files via a separate mount / passthrough= list.")

    # Suggested mount commands per immediate subdir that has any mirrored
    # content (ciphertext and/or mirrored plaintext).
    flag = "--passdata " if mirror_plaintext else ""
    subs = sorted({Path(s.relative_to(install_dir).as_posix()).parts[0]
                   for s, _ in (enc_jobs + copy_jobs)
                   if s.relative_to(install_dir).parts})
    if subs:
        print("\n  Suggested mount (key-free — each file embeds its own key):")
        for sub in subs:
            print(f"    sudo antirev-mount {flag}{output_dir/sub} {install_dir/sub}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
