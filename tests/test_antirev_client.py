#!/usr/bin/env python3
"""Tests for antirev_client — no running daemon required."""

import ctypes as ct
import os
import struct
import sys
import tempfile

# Make tools/ importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
from antirev_client import (
    _aes256_ecb_block, _compute_sock_name, _load_key, AntirevClient,
)

PASS = 0
FAIL = 0

def check(name, got, expected):
    global PASS, FAIL
    if got == expected:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}: got {got!r}, expected {expected!r}")


# ── 1. AES-256-ECB (the former segfault) ────────────────────────────

print("[1] _aes256_ecb_block")

# Test vector: key=0xAA*32, plaintext=0x00*16
# Reference from: openssl enc -aes-256-ecb -nopad -K aa..aa
key = b'\xaa' * 32
pt  = b'\x00' * 16
ct_expected = bytes.fromhex("d44800b981c4e65817f87dfe47b229ed")

ct_got = _aes256_ecb_block(key, pt)
check("known vector", ct_got, ct_expected)

# Different key should give different output
ct_got2 = _aes256_ecb_block(b'\xbb' * 32, pt)
check("different key != same output", ct_got2 != ct_expected, True)

# ── 2. Socket name derivation ───────────────────────────────────────

print("[2] _compute_sock_name")

name = _compute_sock_name(key)
check("starts with antirev_", name.startswith("antirev_"), True)
# antirev_ (8 chars) + 16 hex chars = 24 total
check("length is 24", len(name), 24)
# Deterministic
check("deterministic", _compute_sock_name(key), name)

# ── 3. Key loading ──────────────────────────────────────────────────

print("[3] _load_key")

with tempfile.NamedTemporaryFile(suffix='.hex', delete=False) as f:
    f.write((key.hex() + '\n').encode())
    hex_path = f.name

from pathlib import Path
check("hex file", _load_key(Path(hex_path)), key)
os.unlink(hex_path)

# Trailer format: ... [key:32] [magic:8]
trailer_key = b'\xcc' * 32
fake_binary = b'\x7fELF' + b'\x00' * 100 + trailer_key + b'ANTREV01'
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(fake_binary)
    bin_path = f.name

check("trailer extract", _load_key(Path(bin_path)), trailer_key)
os.unlink(bin_path)

# ── 4. patch_ctypes ─────────────────────────────────────────────────

print("[4] patch_ctypes")

# Create a client without connecting to daemon — just test the patch.
# We'll manually set _libs and call patch_ctypes.
client = object.__new__(AntirevClient)
client._key = key
client._libs = {"libfake.so": 999}
client.patch_ctypes()

check("ct.CDLL is patched", hasattr(ct.CDLL, '_antirev_real'), True)

# Verify that non-matching names pass through (will fail to load, but
# should NOT be redirected — the error should mention the original name).
try:
    ct.CDLL("libdoesnotexist_xyz.so")
    check("passthrough non-match", False, True)  # should not succeed
except OSError as e:
    check("passthrough non-match", "libdoesnotexist_xyz" in str(e), True)

# Verify that matching name is redirected to /proc/self/fd/999
try:
    ct.CDLL("libfake.so")
    check("redirect match", False, True)  # fd 999 doesn't exist
except OSError as e:
    check("redirect match", "/proc/self/fd/999" in str(e), True)

# Also test with a full path — basename matching
try:
    ct.CDLL("/some/path/libfake.so")
except OSError as e:
    check("redirect basename match", "/proc/self/fd/999" in str(e), True)

# ── Summary ─────────────────────────────────────────────────────────

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
