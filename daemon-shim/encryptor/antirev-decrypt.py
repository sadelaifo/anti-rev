#!/usr/bin/env python3
"""
antirev-decrypt — reverse an antirev (memfd + daemon) protected tree.

Takes a packed directory (e.g. /root/proj/) where most libs/exes are
encrypted by antirev-pack.py / protect.py and writes back the plaintext
originals.  Three on-disk forms are recognised:

  1. Encrypted lib (keyless container, the daemon/shim form):
         MAGIC(8) + iv(12) + tag(16) + ct
     (or the antirevfs embed-key form  …+ key(32) + MAGIC(8) — auto-detected,
      decryptable with NO --key because the key rides in the trailer)

  2. Protected exe (stub-wrapped bundle):
         stub + [ flags(1) + entry + needed-libs-section ] + trailer
         entry   = name_len(2) + name + iv(12) + tag(16) + ct_len(8) + ct
         trailer = bundle_offset(8) + key(32) + MAGIC(8)
     We extract the main ENTRY's plaintext → the pristine original ELF.
     The "needed-libs" (dependency) section lives in the bundle, NOT inside
     the ELF, so it is dropped automatically — the recovered exe is clean.
     The trailer also carries the deployment key, so exes need no --key.

  3. Plaintext file / symlink / the generated daemon binary (no main entry)
     — left as-is (copied verbatim in --output mode, untouched in-place).

Key handling:
  * --key=FILE  hex keyfile (64 hex chars), same file the packer used.
  * If --key is omitted, the deployment key is recovered automatically from
    the trailer of the first protected exe / daemon (or an embed-key lib).
    Keyless libs can only be decrypted once a key is known by either route.

Dependency info — what is and isn't reversible:
  * EXE needed-libs section  -> removed automatically (separate from the ELF).
  * LIB with an original DT_SONAME -> recovered byte-for-byte (no edit was made).
  * LIB that originally had NO DT_SONAME -> the packer injected
    DT_SONAME = <basename> before encryption; that edit is baked into the
    ciphertext and CANNOT be reverted from the ciphertext alone.  Such libs are
    flagged in the summary (best-effort, needs readelf).  Rare in practice.

Usage:
    antirev-decrypt.py /root/proj --key=proj.key.hex --output=/root/proj_plain
    antirev-decrypt.py /root/proj --in-place                 # overwrite in place
    antirev-decrypt.py /root/proj --version=1.1.0            # cross-check manifest
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

# Reuse the exact constants the packer/crypto use so the formats stay in lockstep.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protect import MAGIC, KEY_SIZE, IV_SIZE, BFLAG_HAS_MAIN  # noqa: E402

TAG_SIZE        = 16
EXE_TRAILER_LEN = 8 + KEY_SIZE + len(MAGIC)   # bundle_offset + key + MAGIC = 48
LIB_TRAILER_LEN = KEY_SIZE + len(MAGIC)       # embed-key form: key + MAGIC  = 40
HDR_LEN         = len(MAGIC) + IV_SIZE + TAG_SIZE  # MAGIC+iv+tag = 36
ELF_MAGIC       = b"\x7fELF"


# ── crypto ───────────────────────────────────────────────────────────
def _gcm_decrypt(key: bytes, iv: bytes, tag: bytes, ct: bytes) -> bytes:
    # cryptography's AEAD wants ciphertext||tag.
    return AESGCM(key).decrypt(iv, ct + tag, None)


# ── classification + parsing ─────────────────────────────────────────
class Decoded:
    __slots__ = ("kind", "iv", "tag", "ct", "key", "orig_name")

    def __init__(self, kind, iv=None, tag=None, ct=None, key=None, orig_name=None):
        self.kind = kind            # 'lib' | 'exe' | 'daemon' | 'plain'
        self.iv, self.tag, self.ct = iv, tag, ct
        self.key = key              # key recovered from this file (exe/embed-key)
        self.orig_name = orig_name  # original basename (exe bundle entry)


def classify(data: bytes) -> Decoded:
    """Inspect raw bytes and return what kind of artifact this is."""
    # 1) Encrypted lib container — starts with MAGIC.
    if data[:len(MAGIC)] == MAGIC:
        embedded = None
        body = data
        # embed-key form: also ends with MAGIC and carries key in the trailer.
        if len(data) >= HDR_LEN + LIB_TRAILER_LEN and data[-len(MAGIC):] == MAGIC:
            embedded = data[-LIB_TRAILER_LEN:-len(MAGIC)]
            body = data[:-LIB_TRAILER_LEN]
        iv  = body[len(MAGIC):len(MAGIC) + IV_SIZE]
        tag = body[len(MAGIC) + IV_SIZE:HDR_LEN]
        ct  = body[HDR_LEN:]
        return Decoded("lib", iv, tag, ct, key=embedded)

    # 2) Stub-wrapped protected binary — ELF stub, MAGIC trailer.
    if data[:4] == ELF_MAGIC and data[-len(MAGIC):] == MAGIC and len(data) > EXE_TRAILER_LEN:
        bundle_offset = struct.unpack("<Q", data[-EXE_TRAILER_LEN:-EXE_TRAILER_LEN + 8])[0]
        key = data[-EXE_TRAILER_LEN + 8:-len(MAGIC)]
        if not (0 < bundle_offset < len(data)):
            return Decoded("plain")
        flags = data[bundle_offset]
        if not (flags & BFLAG_HAS_MAIN):
            return Decoded("daemon", key=key)   # lrxd: no original to recover
        pos = bundle_offset + 1
        try:
            (nlen,) = struct.unpack("<H", data[pos:pos + 2]); pos += 2
            name = data[pos:pos + nlen].decode("utf-8", "replace"); pos += nlen
            iv  = data[pos:pos + IV_SIZE]; pos += IV_SIZE
            tag = data[pos:pos + TAG_SIZE]; pos += TAG_SIZE
            (ctlen,) = struct.unpack("<Q", data[pos:pos + 8]); pos += 8
            ct = data[pos:pos + ctlen]
            if len(ct) != ctlen:
                return Decoded("plain")
        except struct.error:
            return Decoded("plain")
        return Decoded("exe", iv, tag, ct, key=key, orig_name=name)

    # 3) Anything else is plaintext.
    return Decoded("plain")


# ── soname heuristic (best-effort; flags possibly-injected SONAMEs) ───
_HAVE_READELF = shutil.which("readelf") is not None


def _dt_soname(path: Path) -> str | None:
    if not _HAVE_READELF:
        return None
    try:
        out = subprocess.run(["readelf", "-d", str(path)],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if "(SONAME)" in line and "soname: [" in line:
            return line.split("soname: [", 1)[1].rstrip("]\n ")
    return None


# ── per-file work ────────────────────────────────────────────────────
def _decrypt_one(src: Path, dst: Path, dec: Decoded, key: bytes,
                 in_place: bool, dry: bool) -> dict:
    """Decrypt/copy one file. Returns a small result record."""
    rec = {"src": str(src), "kind": dec.kind, "status": "", "soname_warn": False}
    try:
        if dec.kind in ("lib", "exe"):
            use_key = dec.key or key
            if use_key is None:
                rec["status"] = "no-key"
                return rec
            plain = _gcm_decrypt(use_key, dec.iv, dec.tag, dec.ct)
            if not dry:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(plain)
                try:
                    os.chmod(dst, src.stat().st_mode)
                except OSError:
                    pass
            rec["status"] = "decrypted"
            # SONAME-injection heuristic for libs.
            if dec.kind == "lib" and not dry and _HAVE_READELF:
                sn = _dt_soname(dst)
                if sn and sn == dst.name:
                    rec["soname_warn"] = True
        elif dec.kind == "daemon":
            rec["status"] = "skipped-daemon"
            if not in_place and not dry:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        else:  # plain
            rec["status"] = "plaintext"
            if not in_place and not dry:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
    except InvalidTag:
        rec["status"] = "bad-key/tag"
    except Exception as e:  # noqa: BLE001 — report, don't abort the whole run
        rec["status"] = f"error:{e}"
    return rec


# ── key discovery ────────────────────────────────────────────────────
def _load_key_file(p: Path) -> bytes:
    h = p.read_text().strip()
    key = bytes.fromhex(h)
    if len(key) != KEY_SIZE:
        sys.exit(f"[error] key file must contain {KEY_SIZE * 2} hex chars: {p}")
    return key


def main():
    ap = argparse.ArgumentParser(
        description="Decrypt an antirev (memfd+daemon) protected tree.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("indir", help="encrypted input directory, e.g. /root/proj")
    ap.add_argument("--key", metavar="FILE",
                    help="hex keyfile (64 hex chars). If omitted, the key is "
                         "recovered from a protected exe/daemon trailer.")
    ap.add_argument("--output", metavar="DIR",
                    help="write decrypted tree here (default: <indir>_decrypted)")
    ap.add_argument("--in-place", action="store_true",
                    help="overwrite encrypted files in place (DESTRUCTIVE)")
    ap.add_argument("--version", dest="pkg_version", metavar="STR",
                    help="expected package version; cross-checked against "
                         "antirev-pack-manifest.json if present")
    ap.add_argument("--manifest", metavar="FILE",
                    help="explicit path to antirev-pack-manifest.json")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="parallel workers (default: CPU count)")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify only; write nothing")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    indir = Path(args.indir).resolve()
    if not indir.is_dir():
        sys.exit(f"[error] not a directory: {indir}")

    if args.in_place and args.output:
        sys.exit("[error] --in-place and --output are mutually exclusive")
    out_root = (indir if args.in_place
                else Path(args.output).resolve() if args.output
                else indir.parent / f"{indir.name}_decrypted")
    if not args.in_place and out_root == indir:
        sys.exit("[error] --output must differ from the input dir")

    # ── version cross-check against the pack manifest ─────────────────
    man_path = (Path(args.manifest) if args.manifest
                else next((p for p in (indir / "antirev-pack-manifest.json",
                                       indir.parent / "antirev-pack-manifest.json")
                           if p.exists()), None))
    if man_path and man_path.exists():
        try:
            man = json.loads(Path(man_path).read_text())
            mv = man.get("version", "")
            print(f"[decrypt] manifest version: {mv or '(unset)'}  ({man_path})")
            if args.pkg_version and mv and args.pkg_version != mv:
                print(f"[decrypt] WARNING: --version {args.pkg_version!r} != "
                      f"manifest version {mv!r}")
        except (OSError, ValueError):
            pass
    elif args.pkg_version:
        print(f"[decrypt] version: {args.pkg_version}  (no manifest to verify)")

    cli_key = _load_key_file(Path(args.key)) if args.key else None

    # ── pass 1: walk + classify (also recover the key from a trailer) ─
    files: list[tuple[Path, Decoded]] = []
    symlinks: list[Path] = []
    recovered_key = None
    for dirpath, _dirs, names in os.walk(indir, followlinks=False):
        for n in names:
            src = Path(dirpath) / n
            if src.is_symlink():
                symlinks.append(src)
                continue
            try:
                data = src.read_bytes()
            except OSError as e:
                print(f"[decrypt] WARNING: cannot read {src}: {e}")
                continue
            dec = classify(data)
            files.append((src, dec))
            if recovered_key is None and dec.key is not None:
                recovered_key = dec.key

    key = cli_key or recovered_key
    if cli_key and recovered_key and cli_key != recovered_key:
        print("[decrypt] WARNING: --key differs from the key embedded in a "
              "protected exe trailer; using --key.")
    n_enc = sum(1 for _, d in files if d.kind in ("lib", "exe"))
    n_lib_keyless = sum(1 for _, d in files
                        if d.kind == "lib" and d.key is None)
    if key is None and n_enc:
        print("[decrypt] NOTE: no key available — exes with a trailer still "
              "decrypt, keyless libs cannot. Provide --key.")
    if key is None and n_lib_keyless:
        # nothing to recover the key from at all
        pass

    workers = args.jobs if args.jobs > 0 else (os.cpu_count() or 4)

    # ── pass 2: decrypt / copy ────────────────────────────────────────
    def work(item):
        src, dec = item
        rel = src.relative_to(indir)
        dst = src if args.in_place else (out_root / rel)
        return _decrypt_one(src, dst, dec, key, args.in_place, args.dry_run)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(work, files))

    # recreate symlinks (output mode only; in-place leaves them)
    n_links = 0
    if not args.in_place and not args.dry_run:
        for link in symlinks:
            rel = link.relative_to(indir)
            dst = out_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            os.symlink(os.readlink(link), dst)
            n_links += 1

    # ── summary ───────────────────────────────────────────────────────
    by = {}
    for r in results:
        by[r["status"]] = by.get(r["status"], 0) + 1
        if args.verbose:
            print(f"  [{r['kind']:6}] {r['status']:14} {r['src']}")
    soname_libs = [r["src"] for r in results if r["soname_warn"]]
    bad = [r for r in results if r["status"].startswith(("error:", "bad-key", "no-key"))]

    print("\n[decrypt] Summary")
    print(f"  input    : {indir}")
    print(f"  output   : {out_root}{'  (IN-PLACE)' if args.in_place else ''}"
          f"{'  (DRY-RUN)' if args.dry_run else ''}")
    for k in ("decrypted", "plaintext", "skipped-daemon", "bad-key/tag",
              "no-key"):
        if by.get(k):
            print(f"  {k:15}: {by[k]}")
    if n_links:
        print(f"  symlinks       : {n_links}")
    if soname_libs:
        print(f"\n[decrypt] {len(soname_libs)} lib(s) have DT_SONAME == basename. "
              "If any of these originally had NO SONAME, the packer injected it "
              "before encryption and it is NOT reversible from ciphertext:")
        for s in soname_libs[:20]:
            print(f"    - {s}")
        if len(soname_libs) > 20:
            print(f"    ... (+{len(soname_libs) - 20} more)")
    if not _HAVE_READELF:
        print("[decrypt] NOTE: readelf not found — skipped the SONAME-injection check.")
    if bad:
        print(f"\n[decrypt] {len(bad)} file(s) FAILED to decrypt "
              "(wrong key / corrupt / not actually encrypted).")
        for r in bad[:20]:
            print(f"    - [{r['status']}] {r['src']}")
        sys.exit(1)
    print("\n[decrypt] Done.")


if __name__ == "__main__":
    main()
