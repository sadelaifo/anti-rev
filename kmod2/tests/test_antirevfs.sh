#!/bin/bash
# End-to-end test for the antirevfs kernel module.
#
# Builds a test .so, encrypts it into a lower .enc/ tree with the existing
# protect.py encrypt-lib pipeline, loads the module, installs the key in the
# kernel keyring, mounts antirevfs, and verifies:
#   1. decrypted read matches the original plaintext             (decrypt)
#   2. dlopen() of the encrypted lib through the mount works      (loader)
#   3. /proc/<pid>/maps shows the real path, no "memfd:"          (no artifact)
#   4. a plaintext file under the lower tree returns -EIO         (strict mode)
#   5. a whitelisted .json file is served verbatim               (passthrough)
#   6. two processes mmapping the file share physical pages      (page cache)
#
# Requires root (insmod/mount).  Run:  sudo bash test_antirevfs.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/antirevfs.ko"
PROTECT="$ROOT/encryptor/protect.py"
KEYCTL="$KMOD/tools/antirev-keyctl"

PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_test.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod antirevfs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
# A tiny shared library with a known symbol.
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"   # reference plaintext

# Encrypt into the lower tree; protect.py creates the keyfile.
python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null
# Mixed content: a plaintext .so (strict-mode reject) and a whitelisted .json.
echo "not encrypted" > "$ENC/plain.so"
echo '{"ok":true}'   > "$ENC/data.json"

echo "== load module + key + mount =="
insmod "$MOD" || { echo "insmod failed"; exit 1; }
"$KEYCTL" unlock --keyfile "$WORK/key.hex" >/dev/null
mount -t antirevfs -o "ro,passthrough=json" "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs at $MP" || bad "mount missing"

echo "== 1. decrypt correctness =="
if cmp -s "$MP/libtest.so" "$WORK/libtest.plain.so"; then
	ok "decrypted view byte-identical to original plaintext"
else
	bad "decrypted view differs from plaintext"
	ls -l "$MP/libtest.so" "$WORK/libtest.plain.so"
fi
# ciphertext on disk must NOT match plaintext
cmp -s "$ENC/libtest.so" "$WORK/libtest.plain.so" && bad "lower file is plaintext!" || ok "lower .enc file is ciphertext"

echo "== 2/3. dlopen + /proc/maps real path =="
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
	int (*f)(void) = dlsym(h, "antirevfs_answer");
	if (!f) { fprintf(stderr, "dlsym fail\n"); return 3; }
	int r = f();
	/* prove the mapping shows a real path, not memfd: */
	FILE *m = fopen("/proc/self/maps", "r"); char line[512]; int memfd = 0, real = 0;
	while (fgets(line, sizeof line, m)) {
		if (strstr(line, "libtest.so")) { real = 1;
			if (strstr(line, "memfd:")) memfd = 1; }
	}
	fclose(m);
	printf("answer=%d real_path=%d memfd=%d\n", r, real, memfd);
	return r == 42 ? 0 : 4;
}
EOF
gcc -o "$WORK/loader" "$WORK/loader.c" -ldl
OUT="$("$WORK/loader" "$MP/libtest.so")"; RC=$?
echo "    loader: $OUT (rc=$RC)"
[[ $RC -eq 0 ]] && ok "dlopen+dlsym+call returned 42" || bad "dlopen path failed"
echo "$OUT" | grep -q "real_path=1" && ok "lib mapped at real path in /proc/maps" || bad "lib not found in maps"
echo "$OUT" | grep -q "memfd=0"    && ok "no memfd: artifact in /proc/maps"      || bad "memfd: artifact present"

echo "== 4. strict mode (plaintext .so rejected) =="
if cat "$MP/plain.so" >/dev/null 2>&1; then
	bad "plaintext .so was readable (strict mode broken)"
else
	ok "plaintext .so under mount returns error (strict mode)"
fi

echo "== 5. passthrough whitelist (.json) =="
if cmp -s "$MP/data.json" "$ENC/data.json"; then
	ok "whitelisted .json served verbatim"
else
	bad "passthrough .json mismatch"
fi

echo "== 6. cross-process page sharing =="
# Two long-lived readers mmap the same file; compare the physical frame (PFN)
# backing the first text page via /proc/<pid>/pagemap.  Equal PFN => shared.
cat > "$WORK/pfn.c" <<'EOF'
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
int main(int argc, char **argv) {
	int fd = open(argv[1], O_RDONLY); struct stat st; fstat(fd, &st);
	char *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	volatile char c = p[0]; (void)c;            /* fault the page in */
	uintptr_t va = (uintptr_t)p;
	int pm = open("/proc/self/pagemap", O_RDONLY);
	uint64_t ent; pread(pm, &ent, 8, (va/4096)*8);
	uint64_t pfn = (ent & ((1ULL<<55)-1));
	printf("%llu\n", (unsigned long long)((ent>>63)&1 ? pfn : 0));
	fflush(stdout);
	pause();                                     /* keep mapping alive */
	return 0;
}
EOF
gcc -o "$WORK/pfn" "$WORK/pfn.c"
# Run a reader, capture the one PFN line it prints, then kill it (it pauses to
# keep the mapping alive so the PFN is still valid when the second one runs).
get_pfn() { local out; out=$(mktemp); "$WORK/pfn" "$1" >"$out" & local pid=$!; sleep 0.3; head -1 "$out"; kill "$pid" 2>/dev/null; rm -f "$out"; }
pfn1=$(get_pfn "$MP/libtest.so")
pfn2=$(get_pfn "$MP/libtest.so")
echo "    pfn1=$pfn1 pfn2=$pfn2"
if [[ -n "$pfn1" && "$pfn1" != "0" && "$pfn1" == "$pfn2" ]]; then
	ok "two processes share the same physical page (PFN $pfn1)"
else
	bad "page not shared (pfn1=$pfn1 pfn2=$pfn2) — may need CAP_SYS_ADMIN for pagemap PFNs"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
