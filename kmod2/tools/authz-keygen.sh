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

# Config-file extensions (works on old openssl 1.0.2, which lacks -addext).
# A module-signing-style leaf: CA:FALSE + keyUsage=digitalSignature — the kernel
# accepts this self-signed cert as a trust anchor in the authz keyring, and it's
# a valid CMS/PKCS#7 signer.
CFG="$OUT/.authz_req.cnf"
cat > "$CFG" <<'CFGEOF'
[req]
distinguished_name = dn
x509_extensions    = v3
prompt             = no
[dn]
CN = vcache authorization key
[v3]
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature
subjectKeyIdentifier = hash
CFGEOF
openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
    -config "$CFG" \
    -keyout "$OUT/authz_priv.pem" -out "$OUT/authz_cert.pem" || { rm -f "$CFG"; exit 1; }
rm -f "$CFG"
openssl x509 -in "$OUT/authz_cert.pem" -outform DER -out "$OUT/authz_cert.der"
chmod 600 "$OUT/authz_priv.pem"

echo "[authz-keygen] wrote:"
echo "  $OUT/authz_priv.pem  (SECRET — keep off client machines)"
echo "  $OUT/authz_cert.pem  (PEM cert)"
echo "  $OUT/authz_cert.der  (DER cert -> embed via authz-embed-pubkey.sh)"
