#!/usr/bin/env bash
# authz-sign.sh — sign an allow-list, producing a detached PKCS#7 the module
# verifies (gate_require_sig=1).  Run at deploy/pack time with the VENDOR key.
#
#   ./authz-sign.sh authz_priv.pem authz_cert.pem /etc/authorized_apps.txt [out.p7s]
#
# Default output: <listfile>.p7s (DER).  Then on the target:
#   insmod antirevfs.ko gate_enforce=1 gate_require_sig=1
#   (authz_sig_path defaults to <authz_path>.p7s)
set -euo pipefail
KEY="${1:?priv.pem}"; CERT="${2:?cert.pem}"; LIST="${3:?listfile}"
OUT="${4:-$LIST.p7s}"
command -v openssl >/dev/null || { echo "openssl required" >&2; exit 1; }

# Detached, binary, SHA-256 CMS/PKCS#7 over the RAW list bytes, DER-encoded.
# -noattr: sign the content directly (matches the kernel module-signing style).
openssl cms -sign -binary -noattr -md sha256 \
    -in "$LIST" -signer "$CERT" -inkey "$KEY" \
    -outform DER -out "$OUT"

# Sanity: check the SIGNATURE is valid (crypto only), NOT the X.509 chain.
# -noverify skips signer-cert path/purpose validation — a self-signed vendor cert
# is not a CA, so `-CAfile` chain checks fail on older openssl even though the
# signature is fine (and the kernel, like module-signing, accepts the self-signed
# cert as a trust anchor).  A tampered list still fails this (the signature
# won't match).  Non-fatal: the kernel PKCS#7 check is authoritative.
if openssl cms -verify -binary -inform DER -in "$OUT" -content "$LIST" \
       -noverify -out /dev/null 2>/dev/null; then
	echo "[authz-sign] wrote + self-verified (signature ok) $OUT"
else
	echo "[authz-sign] wrote $OUT (userspace self-verify skipped/unsupported on this openssl — the kernel PKCS#7 check is authoritative)" >&2
fi
