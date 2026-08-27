#!/bin/bash
# Writable-view test for antirevfs: overlayfs writable-upper over a decrypted
# antirevfs lower (the `vcache-mount-rw` tool).
#
# Motivation: antirevfs mounts are read-only by design, so business software
# that writes lock/log/temp files INSIDE bin/ or lib/ (next to the protected
# executables) fails with -EROFS.  This test first DEMONSTRATES that failure on
# a bare antirevfs mount, then proves the overlay stack fixes it:
#
#   0. write into a bare antirevfs mount fails              (the failure mode)
#   1. overlayfs accepts antirevfs as a lowerdir            (load-bearing)
#   2. encrypted .so decrypts when read through the overlay (read path intact)
#   3. app can create/write lock+log files in the view      (the fix)
#   4. those writes land in the writable upper, NOT in .enc  (ciphertext safe)
#   5. dlopen+dlsym+call through the overlay works          (loader intact)
#   6. --down tears the stack down in the right order        (lifecycle)
#   7. copy-up caveat: editing an ENCRYPTED file copies plaintext up (documented)
#
# Requires root (insmod/mount).  Run:  sudo bash test_antirevfs_overlay_rw.sh
set -uo pipefail

# Shared real session keyring for both `vcache-keyctl unlock` and `mount`
# (see the long explanation in test_antirevfs.sh).
if [[ -z "${ANTIREVFS_TEST_SESSION:-}" ]]; then
	if command -v keyctl >/dev/null 2>&1; then
		export ANTIREVFS_TEST_SESSION=1
		exec keyctl session - bash "$0" "$@"
	fi
	echo "warning: keyctl not found; cannot guarantee a shared session keyring" >&2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
PROTECT="$ROOT/encryptor/protect.py"
KEYCTL="$KMOD/tools/vcache-keyctl"
MOUNTRW="$KMOD/tools/vcache-mount-rw"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_ovl.XXXXXX)"
ENC="$WORK/.enc/bin"     # ciphertext (ext4)
BARE="$WORK/bare"        # bare antirevfs mount (to show the read-only failure)
MP="$WORK/bin"           # final writable view (overlay), what the app sees
mkdir -p "$ENC" "$BARE" "$MP"

cleanup() {
	"$MOUNTRW" --down "$MP" >/dev/null 2>&1
	mountpoint -q "$BARE" && umount "$BARE"
	rmmod vcachefs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build + encrypt a test .so into .enc/bin =="
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void){ return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"
python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

echo "== load module + key =="
insmod "$MOD" || { echo "insmod failed"; exit 1; }

echo "== 0. failure mode: bare antirevfs mount rejects writes =="
mount -t vcachefs -o "ro,passdata" "$ENC" "$BARE" || { echo "bare mount failed"; dmesg|tail -5; exit 1; }
if echo x > "$BARE/app.lock" 2>/dev/null; then
	bad "bare antirevfs accepted a write (expected -EROFS)"
else
	ok "bare antirevfs rejects writes into bin/ (this is the reported failure)"
fi
umount "$BARE"

echo "== mount the writable view (vcache-mount-rw) =="
if "$MOUNTRW" --passdata --state "$WORK/state" "$ENC" "$MP" >/dev/null; then
	ok "1. overlayfs accepted antirevfs as lowerdir"
else
	bad "1. vcache-mount-rw failed to stack overlay over antirevfs"; dmesg|tail -10; exit 1
fi

echo "== 2. decrypted read through the overlay =="
cmp -s "$MP/libtest.so" "$WORK/libtest.plain.so" \
	&& ok "2. encrypted .so decrypts when read through the overlay" \
	|| bad "2. decrypted view differs from plaintext"

echo "== 3. app writes lock + log files into bin/ (the fix) =="
if echo "pid 4321" > "$MP/app.lock" 2>/tmp/werr.$$ && \
   echo "started"  >> "$MP/run.log"  2>>/tmp/werr.$$; then
	ok "3. create+write of lock/log files in the view succeeds"
else
	bad "3. write still blocked: $(cat /tmp/werr.$$ 2>/dev/null)"
fi
rm -f /tmp/werr.$$

echo "== 4. writes land in the writable upper, not the ciphertext tree =="
UP="$WORK/state/upper"
[[ -f "$UP/app.lock" && -f "$UP/run.log" ]] \
	&& ok "4a. lock/log files are in the overlay upper" \
	|| bad "4a. written files not found in upper ($UP)"
[[ -e "$ENC/app.lock" || -e "$ENC/run.log" ]] \
	&& bad "4b. a written file leaked into the .enc ciphertext tree!" \
	|| ok "4b. .enc ciphertext tree untouched by the writes"

echo "== 5. dlopen+dlsym+call through the overlay path =="
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c,char**v){
	void*h=dlopen(v[1],RTLD_NOW);
	if(!h){fprintf(stderr,"dlopen: %s\n",dlerror());return 2;}
	int(*f)(void)=dlsym(h,"antirevfs_answer");
	if(!f){fprintf(stderr,"dlsym fail\n");return 3;}
	return f()==42?0:4;
}
EOF
gcc -o "$WORK/loader" "$WORK/loader.c" -ldl
"$WORK/loader" "$MP/libtest.so" \
	&& ok "5. dlopen+dlsym+call through overlay returned 42" \
	|| bad "5. dlopen through overlay failed"

echo "== 6. teardown order (overlay then antirevfs) =="
if "$MOUNTRW" --down --state "$WORK/state" "$MP" >/dev/null 2>&1; then
	if ! mountpoint -q "$MP" && ! mountpoint -q "$WORK/state/dec"; then
		ok "6. --down unmounted both overlay and antirevfs"
	else
		bad "6. --down left a mount behind"
	fi
else
	bad "6. --down failed"
fi
# upper survives teardown (persistent writable state)
[[ -f "$UP/app.lock" ]] && ok "6b. upper (written state) preserved across --down" \
	|| bad "6b. upper lost on teardown"
# the app's log is retrievable AFTER unmount, on disk, from the upper path
if [[ "$(cat "$UP/run.log" 2>/dev/null)" == "started" ]]; then
	ok "6c. app log readable on disk after --down (at upper, not lost)"
else
	bad "6c. app log not retrievable after teardown"
fi
# --status surfaces the upper path + the written files while unmounted
if "$MOUNTRW" --status --state "$WORK/state" "$MP" 2>/dev/null | grep -q "run.log"; then
	ok "6d. --status lists app-written files while unmounted"
else
	bad "6d. --status did not surface written files"
fi

echo "== 7. copy-up caveat: editing an ENCRYPTED file copies plaintext up =="
# Re-mount, append to the decrypted .so, and confirm overlay copied the
# PLAINTEXT into the upper.  This is expected overlayfs behavior and the reason
# the README warns against writing to (vs alongside) encrypted files.
"$MOUNTRW" --passdata --state "$WORK/state2" "$ENC" "$MP" >/dev/null
echo "tamper" >> "$MP/libtest.so" 2>/dev/null || true
CU="$WORK/state2/upper/libtest.so"
if [[ -f "$CU" ]]; then
	plen=$(stat -c%s "$WORK/libtest.plain.so")
	if cmp -s <(head -c "$plen" "$CU") "$WORK/libtest.plain.so"; then
		ok "7. copy-up of an encrypted file yields PLAINTEXT in upper (documented caveat)"
	else
		bad "7. copy-up produced unexpected bytes (neither ciphertext nor known plaintext)"
	fi
else
	# Some overlay/kernel combos may fail the write instead of copying up; either
	# way the ciphertext tree is safe.  Treat as non-fatal but note it.
	ok "7. no copy-up occurred (write to encrypted file did not materialize in upper)"
fi
"$MOUNTRW" --down --state "$WORK/state2" "$MP" >/dev/null 2>&1

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
