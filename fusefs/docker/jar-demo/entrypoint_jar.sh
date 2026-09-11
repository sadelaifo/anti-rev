#!/usr/bin/env bash
# entrypoint_jar.sh — in-container proof that the JVM runs an ENCRYPTED .jar
# through the fusefs mount (gate on `java`), while a copy (`cp`) gets a keyless
# container that is not a valid jar.
set -u
LOWER=/opt/app.enc
MNT=/opt/app
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
wait_mounted() { i=0; while ! grep -q " $1 " /proc/self/mountinfo; do i=$((i+1)); [ $i -gt 50 ] && return 1; sleep 0.1; done; }

echo "== [container] java = $(readlink -f "$(command -v java)") =="
mkdir -p "$MNT"
echo java > /etc/authz.txt          # authorize the JVM by basename
vcachefsd "$LOWER" "$MNT" --passdata --gate --authz /etc/authz.txt --passthrough-cipher
wait_mounted "$MNT" || { echo "  FAIL: mount"; echo; echo "0 passed, 1 failed"; exit 1; }
ok "fusefs mounted (gate on: java)"

# 1. authorized: java runs the encrypted jar straight off the mount
OUT=$(java -jar "$MNT/app.jar" 2>&1)
if [ "$OUT" = "Hello from encrypted jar" ]; then
	ok "java -jar ran the ENCRYPTED jar through the mount"
else
	bad "java -jar failed: $OUT"
fi

# 2. lower file is ciphertext on disk
head -c8 "$LOWER/app.jar" | cmp -s - <(printf '\xa7\x4c\x2e\x91\xd6\x3b\x08\x5f') \
	&& ok "lower app.jar is ciphertext (FS_MAGIC)" || bad "lower not ciphertext"

# 3. unauthorized copy (cp) -> keyless container (trailer stripped)
cp "$MNT/app.jar" /tmp/copy.jar 2>/dev/null
ENC=$(stat -c %s "$LOWER/app.jar"); WANT=$((ENC-40)); GOT=$(stat -c %s /tmp/copy.jar)
[ "$GOT" = "$WANT" ] && ok "cp yields container-40 bytes ($GOT), key stripped" || bad "cp size $GOT != $WANT"

# 4. the copied bytes are NOT a usable jar
if jar tf /tmp/copy.jar >/dev/null 2>&1; then
	bad "copied jar is still a valid archive (leak!)"
else
	ok "copied jar is not a valid archive (jar tf refuses it)"
fi
if java -jar /tmp/copy.jar >/dev/null 2>&1; then
	bad "java ran the copied keyless jar (leak!)"
else
	ok "java refuses to run the keyless copy"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
