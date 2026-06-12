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
#   7. passdata serves any non-magic file plaintext              (mixed tree)
#   8. symlinks (chains, ->encrypted lib, ->data) resolve        (get_link)
#
# Requires root (insmod/mount).  Run:  sudo bash test_antirevfs.sh
set -uo pipefail

# Re-exec under a fresh, real session keyring shared by every child below this
# point (the `antirev-keyctl` unlock AND the later `mount`).  The module's
# request_key() runs in the mount process's context, so the key must live in a
# session keyring that process inherits.  On a root shell that has no session
# keyring of its own (SLES `su`, ssh/cron root, etc.), `keyctl padd @s` would
# otherwise create an *ephemeral* session keyring local to the keyctl process,
# which vanishes before `mount` runs -> request_key() returns -ENOKEY and every
# decrypted read fails with "Required key not available".  A login session that
# already owns a `_ses` (a desktop dev box) masks the bug; this re-exec makes
# the test pass regardless of the starting environment.
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
MOD="$KMOD/module/antirevfs.ko"
PROTECT="$ROOT/encryptor/protect.py"
KEYCTL="$KMOD/tools/antirev-keyctl"

PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_test.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; MP2="$WORK/lib_pd"
mkdir -p "$ENC" "$MP" "$MP2"

cleanup() {
	mountpoint -q "$MP2" && umount "$MP2"
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
# A real plaintext ELF (third-party lib that coexists) + a script with no
# whitelisted extension — both rejected by strict mode, both served by passdata.
cp "$WORK/libtest.plain.so" "$ENC/thirdparty.so"
printf '#!/bin/sh\necho hi\n' > "$ENC/run.sh"
# Symlinks mirrored into the lower tree (as the packer does): a chain to the
# ENCRYPTED lib, a link to a passthrough data file, and a genuinely broken link.
ln -s libtest.so   "$ENC/lib_link.so"     # symlink -> encrypted lib (decrypts)
ln -s lib_link.so  "$ENC/lib_link2.so"    # chained symlink (SONAME-style)
ln -s data.json    "$ENC/data_link.json"  # symlink -> passthrough data file
ln -s nonexistent  "$ENC/broken_link"     # genuinely dangling target

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

echo "== 7. passdata mode (complete mixed-content read-only tree) =="
# Same lower tree, mounted with passdata: ANY non-ANTREV01 file is served
# plaintext (data files, scripts, third-party plaintext ELFs), while encrypted
# libs still decrypt.  This is the mixed bin/lib case from antirev-fs-pack.py
# with mirror_plaintext.  Strict mode rejected thirdparty.so / run.sh above;
# passdata serves them.
if mount -t antirevfs -o "ro,passdata" "$ENC" "$MP2" 2>/dev/null; then
	ok "mounted antirevfs with passdata"
	# encrypted lib still decrypts
	cmp -s "$MP2/libtest.so" "$WORK/libtest.plain.so" \
		&& ok "passdata: encrypted lib still decrypts" \
		|| bad "passdata: encrypted lib decrypt broke"
	# third-party plaintext ELF served byte-identically (strict mode rejected it)
	cmp -s "$MP2/thirdparty.so" "$WORK/libtest.plain.so" \
		&& ok "passdata: plaintext third-party ELF served verbatim" \
		|| bad "passdata: third-party ELF not served"
	# script with no whitelisted extension served plaintext
	cmp -s "$MP2/run.sh" "$ENC/run.sh" \
		&& ok "passdata: unlisted-extension script served verbatim" \
		|| bad "passdata: script not served"
	umount "$MP2"
else
	bad "passdata mount failed"
	dmesg | tail -5
fi

echo "== 8. symlinks resolve through the mount =="
# readlink must work (regression: module used to reject S_IFLNK with -EINVAL,
# so every symlink showed l????????? and dangled).
if [[ "$(readlink "$MP/lib_link.so" 2>/dev/null)" == "libtest.so" ]]; then
	ok "readlink through mount returns the target"
else
	bad "readlink through mount empty/wrong (symlink not served)"
fi
# symlink -> encrypted lib resolves AND decrypts
cmp -s "$MP/lib_link.so" "$WORK/libtest.plain.so" \
	&& ok "symlink -> encrypted lib resolves + decrypts" \
	|| bad "symlink -> encrypted lib broken"
# chained symlink (lib_link2 -> lib_link.so -> libtest.so)
cmp -s "$MP/lib_link2.so" "$WORK/libtest.plain.so" \
	&& ok "chained symlink resolves (SONAME-style)" \
	|| bad "chained symlink broken"
# symlink -> passthrough data file
cmp -s "$MP/data_link.json" "$ENC/data.json" \
	&& ok "symlink -> passthrough data resolves" \
	|| bad "symlink -> data broken"
# a genuinely broken link must still dangle (not crash, not falsely resolve)
if readlink "$MP/broken_link" >/dev/null 2>&1 && ! cat "$MP/broken_link" >/dev/null 2>&1; then
	ok "genuinely-broken link readable as a link but dangles (correct)"
else
	bad "broken link misbehaved"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
