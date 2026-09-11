#!/usr/bin/env bash
# entrypoint.sh — runs INSIDE the container: mount vcachefsd over the baked
# ciphertext tree, then assert decrypt/gate behaviour.  Proves the unverified
# path: a FUSE decrypt mount working inside a container's mount namespace, with
# the gate resolving caller identity container-relative (/proc/<pid>/exe).
set -u
LOWER=/opt/product.enc
MNT=/opt/product
EXPECT=/opt/expected
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== [container] env =="
echo "  pid1=$(readlink /proc/1/exe 2>/dev/null); mnt-ns=$(readlink /proc/self/ns/mnt)"
ls -l /dev/fuse 2>&1 | sed 's/^/  /'

mkdir -p "$MNT"
# authorize a uniquely-named reader by basename (container-local /etc path)
READER=/usr/local/bin/okreader; cp "$(command -v cat)" "$READER"
echo "okreader" > /etc/authz.txt

echo "== [container] mount vcachefsd (gate + passthrough-cipher) =="
vcachefsd "$LOWER" "$MNT" --passdata --gate --authz /etc/authz.txt --passthrough-cipher
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
if ! mountpoint -q "$MNT"; then
	echo "  FAIL: vcachefsd did not mount inside the container"
	echo; echo "0 passed, 1 failed"; exit 1
fi
ok "vcachefsd mounted inside the container ($(grep -m1 "$MNT" /proc/self/mountinfo | awk '{print $NF}'))"

# 1. authorized decrypt
if cmp -s <("$READER" "$MNT/secret.so") "$EXPECT"; then
	ok "authorized reader decrypts through the in-container mount"
else
	bad "authorized decrypt mismatch"
fi
# 2. lower is ciphertext on disk
if head -c8 "$LOWER/secret.so" | cmp -s - <(printf '\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f'); then
	ok "lower file is ciphertext (FS_MAGIC on disk)"
else
	bad "lower file not ciphertext"
fi
# 3. passdata passthrough of a plaintext data file
[ "$(cat "$MNT/notes.txt")" = "third-party plaintext" ] && ok "plaintext data file served verbatim" || bad "passdata passthrough wrong"
# 4. unauthorized reader -> keyless container (gate keys on caller identity)
ENC=$(stat -c %s "$LOWER/secret.so"); WANT=$((ENC-40))
cat "$MNT/secret.so" > /tmp/copied.bin 2>/dev/null
GOT=$(stat -c %s /tmp/copied.bin)
[ "$GOT" = "$WANT" ] && ok "unauthorized cat -> container-40 bytes ($GOT), key trailer stripped" || bad "unauthorized size $GOT != $WANT"
cmp -s /tmp/copied.bin "$EXPECT" && bad "unauthorized copy leaked PLAINTEXT" || ok "unauthorized copy is not plaintext"

fusermount3 -u "$MNT" 2>/dev/null
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
