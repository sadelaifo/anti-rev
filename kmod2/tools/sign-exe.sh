#!/bin/bash
# sign-exe.sh — vendor-sign a PLAINTEXT executable (e.g. the technician's
# vcache-coredbg) with the per-exe signature footer the vcachefs gate verifies, WITHOUT
# encrypting it.  The signed binary still runs normally — the footer is trailing
# bytes after the ELF's last segment, which the loader ignores — while the gate
# reads the footer and authorizes the running process to read decrypted content
# (encrypted binaries / .debug) through the mount.
#
# Footer is byte-identical to shared/vcache-pack.py's per-exe signing:
#     [exe bytes][sig][sig_len:4 LE][SIG_MAGIC:8]
#   sig       = openssl cms -sign -binary -noattr -md sha256 -outform DER
#               (detached PKCS#7/CMS over the exe bytes — exactly what the
#                kernel's verify_pkcs7_signature accepts)
#   SIG_MAGIC = 3d6af0128c55b427   (== ANTREV_SIG_MAGIC in module/vcachefs.h)
#
# The matching vendor cert (DER) must be embedded in the module
# (module/gate_authz_pubkey.h, via authz-embed-pubkey.sh) and the .ko rebuilt,
# or signature verification fails closed and every caller is denied.
#
# Keep the vendor PRIVATE key off client machines — sign in-house only.
#
# Usage:  sign-exe.sh <vendor.key> <vendor.crt> <exe> [out]
#   default out = <exe>.signed ; pass the same path as <exe> to sign in place.
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: $0 <vendor.key> <vendor.crt> <exe> [out]" >&2; exit 2; }
KEY=$1; CERT=$2; EXE=$3; OUT=${4:-$EXE.signed}

for f in "$KEY" "$CERT" "$EXE"; do
	[ -r "$f" ] || { echo "sign-exe: cannot read $f" >&2; exit 1; }
done
command -v openssl >/dev/null || { echo "sign-exe: openssl not in PATH" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# 1) detached PKCS#7/CMS (DER, SHA-256, no signed attrs) over the EXACT exe bytes
openssl cms -sign -binary -noattr -md sha256 \
	-in "$EXE" -signer "$CERT" -inkey "$KEY" -outform DER > "$tmp/sig.der"
siglen=$(wc -c < "$tmp/sig.der")

# 2) footer = sig || sig_len(4 LE) || SIG_MAGIC(8)
#    (bash printf '\xNN'; the inner printf builds the \x-escaped LE length)
{
	cat "$tmp/sig.der"
	printf "$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' \
		$(( siglen        & 255)) \
		$(((siglen >>  8) & 255)) \
		$(((siglen >> 16) & 255)) \
		$(((siglen >> 24) & 255)) )"
	printf '\x3d\x6a\xf0\x12\x8c\x55\xb4\x27'
} > "$tmp/foot.bin"

# 3) assemble [exe][footer]  (via tmp, so signing in place is safe)
cat "$EXE" "$tmp/foot.bin" > "$tmp/out.bin"
chmod --reference="$EXE" "$tmp/out.bin" 2>/dev/null || chmod 0755 "$tmp/out.bin"
mv -f "$tmp/out.bin" "$OUT"

echo "sign-exe: wrote $OUT"
echo "  exe bytes : $(wc -c < "$EXE")"
echo "  sig bytes : $siglen"
echo "  total     : $(wc -c < "$OUT")"
command -v sha256sum >/dev/null && echo "  sha256    : $(sha256sum "$OUT" | cut -d' ' -f1)"

# self-check: the detached sig verifies against the exe + cert (not a trust
# check of the cert chain — just that key/cert/content are consistent)
if openssl cms -verify -binary -noattr -inform DER -in "$tmp/sig.der" \
	-content "$EXE" -certfile "$CERT" -no_signer_cert_verify -out /dev/null 2>/dev/null; then
	echo "  verify    : OK"
else
	echo "  verify    : WARNING — self-check failed; check the key/cert pair" >&2
fi
