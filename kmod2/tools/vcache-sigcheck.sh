#!/bin/bash
# vcache-sigcheck.sh — does a file carry the vcachefs per-exe signature footer,
# and (with --cert) does that signature VERIFY against the vendor cert?
#
# The gate authorizes an encrypted exec-load only if the file's own container
# carries a valid signature.  The footer (appended by shared/vcache-pack.py and
# kmod2/tools/sign-exe.sh) is:
#     [ signed bytes ][ sig : DER PKCS#7 ][ sig_len : 4 bytes LE ][ SIG_MAGIC : 8 ]
#     SIG_MAGIC = 3d6af0128c55b427
# `signed bytes` is the whole ANTREV container for an encrypted exe, or the whole
# ELF for a plaintext sign-exe.sh'd binary — the footer format is identical.
#
# Usage:
#   vcache-sigcheck.sh FILE...                     # presence only (no key needed)
#   vcache-sigcheck.sh --cert vendor.{pem,der} FILE...   # full PKCS#7 verify
#   # scan a whole tree:
#   find bin -type f -exec vcache-sigcheck.sh --cert vendor.pem {} +
#
# Exit 0 iff every FILE is SIGNED (and VERIFIED when --cert is given).
set -u
MAGIC_HEX=3d6af0128c55b427

CERT=""
if [ "${1:-}" = "--cert" ]; then CERT=$2; shift 2; fi
[ $# -ge 1 ] || { echo "usage: $0 [--cert vendor.{pem,der}] FILE..." >&2; exit 2; }

# Normalise the cert to PEM (openssl cms -certfile wants PEM).
CERTPEM=""; CERT_TMP=""
if [ -n "$CERT" ]; then
	[ -r "$CERT" ] || { echo "cannot read cert: $CERT" >&2; exit 2; }
	command -v openssl >/dev/null || { echo "openssl not in PATH (needed for --cert)" >&2; exit 2; }
	if grep -q "BEGIN CERTIFICATE" "$CERT" 2>/dev/null; then
		CERTPEM="$CERT"
	else
		CERT_TMP=$(mktemp); CERTPEM="$CERT_TMP"
		openssl x509 -inform DER -in "$CERT" -out "$CERTPEM" 2>/dev/null \
			|| { echo "cert is neither PEM nor DER x509: $CERT" >&2; rm -f "$CERT_TMP"; exit 2; }
	fi
fi
cleanup() { [ -n "$CERT_TMP" ] && rm -f "$CERT_TMP"; }
trap cleanup EXIT

rc=0
for f in "$@"; do
	[ -r "$f" ] || { echo "UNREADABLE  $f"; rc=1; continue; }
	sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
	if [ "$sz" -lt 20 ]; then echo "UNSIGNED    $f (too small)"; rc=1; continue; fi

	mag=$(tail -c8 "$f" | xxd -p | tr -d '\n')
	if [ "$mag" != "$MAGIC_HEX" ]; then
		echo "UNSIGNED    $f (no footer magic: ...$mag)"; rc=1; continue
	fi

	lenhex=$(tail -c12 "$f" | head -c4 | xxd -p | tr -d '\n')
	siglen=$(python3 -c "print(int.from_bytes(bytes.fromhex('$lenhex'),'little'))" 2>/dev/null)
	if [ -z "$siglen" ] || [ "$siglen" -le 0 ] || [ "$siglen" -gt $((sz - 12)) ]; then
		echo "SUSPECT     $f (footer magic present but bad sig_len='$siglen')"; rc=1; continue
	fi

	if [ -z "$CERTPEM" ]; then
		echo "SIGNED      $f (footer present, sig_len=$siglen; pass --cert to verify)"
		continue
	fi

	clen=$((sz - 12 - siglen))
	tmp=$(mktemp -d)
	head -c "$clen" "$f" > "$tmp/content"
	tail -c $((siglen + 12)) "$f" | head -c "$siglen" > "$tmp/sig.der"
	# Use the vendor cert as the TRUST ANCHOR (-CAfile), matching the kernel gate,
	# which requires the signer to chain to the embedded vendor key.  NOT -noverify
	# and NOT -certfile alone: `cms -sign` embeds the signer cert in the signature,
	# so -noverify/-certfile would "verify" ANY self-consistent signature (wrong
	# key included).  -partial_chain lets a self-signed vendor cert act as the
	# anchor without CA:TRUE basic constraints.
	if openssl cms -verify -binary -noattr -inform DER -in "$tmp/sig.der" \
		-content "$tmp/content" -CAfile "$CERTPEM" -partial_chain \
		-out /dev/null 2>/dev/null; then
		echo "VERIFIED    $f (signature valid against $(basename "$CERT"))"
	else
		echo "INVALID     $f (footer present but does NOT verify — wrong key or altered bytes)"
		rc=1
	fi
	rm -rf "$tmp"
done
exit $rc
