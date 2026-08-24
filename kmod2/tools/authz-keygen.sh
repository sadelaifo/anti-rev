#!/usr/bin/env bash
# authz-keygen.sh — generate the VENDOR authorization keypair (run ONCE, keep
# the private key secret — it never ships to clients).
#
#   ./authz-keygen.sh [outdir]
#
# Produces in <outdir> (default ./authz-keys):
#   authz_priv.pem   RSA private key   (SECRET — sign allow-lists with this)
#   authz_cert.pem   self-signed X.509 (PEM) — for openssl signing/verify
#   authz_cert.der   same cert in DER  — embed into the module (authz-embed-pubkey.sh)
#
# The module carries only the PUBLIC key (via gate_authz_pubkey.h); clients get
# the module + a signed list and can neither edit nor forge the allow-list.
set -euo pipefail
OUT="${1:-./authz-keys}"; mkdir -p "$OUT"
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }

openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
    -keyout "$OUT/authz_priv.pem" -out "$OUT/authz_cert.pem" \
    -subj "/CN=antirev authorization key" \
    -addext "keyUsage=critical,digitalSignature" 2>/dev/null \
  || openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
    -keyout "$OUT/authz_priv.pem" -out "$OUT/authz_cert.pem" \
    -subj "/CN=antirev authorization key"    # fallback: older openssl w/o -addext
openssl x509 -in "$OUT/authz_cert.pem" -outform DER -out "$OUT/authz_cert.der"
chmod 600 "$OUT/authz_priv.pem"

echo "[authz-keygen] wrote:"
echo "  $OUT/authz_priv.pem  (SECRET — keep off client machines)"
echo "  $OUT/authz_cert.pem  (PEM cert)"
echo "  $OUT/authz_cert.der  (DER cert -> embed via authz-embed-pubkey.sh)"
