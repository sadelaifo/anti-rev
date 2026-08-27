#!/bin/bash
# test_proj_setup.sh — end-to-end reproduction of the process-manager business
# stack on antirevfs, in its REAL production shape:
#
#   * ciphertext tree built by vcache-pack.py from a ~/proj-style layout
#       bin/<module>/{procmgr,executable_x}      encrypted executables
#       lib/link/<module>/libxxx.so              encrypted business lib
#       lib/link/sw/libPreload.so                global LD_PRELOAD shim (PLAINTEXT)
#       lib/link/3rd/libFoo.so                   third-party dep of preload (PLAINTEXT)
#   * BOTH bin/ and lib/ mounted as WRITABLE overlay views (vcache-mount-rw)
#   * decrypt-authorization GATE enforced (gate_enforce=1), allow-list by BASENAME
#   * a process manager that fork/execs the child by RELATIVE path (cwd=proj),
#     arg "executable_x,1", with the global LD_PRELOAD + recursive LD_LIBRARY_PATH
#
# This is the one test that combines overlay-rw + gate + exec-load + lib-load +
# global plaintext preload, which no other test covers. In particular it proves
# the load-bearing-but-unverified claim that the exec-load gate fires correctly
# through the overlayfs backing file (FMODE_EXEC/__FMODE_EXEC propagation).
#
# Checks:
#   1. packer classifies procmgr/executable_x/libxxx.so encrypted; libPreload.so
#      + libFoo.so plaintext (blacklisted); on-disk magic confirms it
#   2. END-TO-END: with {procmgr,executable_x} whitelisted, the relative-path
#      fork/exec chain runs — procmgr loads its encrypted lib, spawns the child,
#      the child loads its encrypted lib AND the global plaintext preload (+its
#      3rd-party dep), and prints CHILD_OK:42   <-- closes the overlay exec-load Q
#   3. the child's runtime lock write lands in the overlay UPPER, never in .enc
#   4. drop executable_x from the allow-list -> its exec-load is DENIED (gate
#      keys on the program's own basename through the overlay backing file)
#   5. drop procmgr from the allow-list -> procmgr can't even exec-load
#   6. `cp` of the encrypted lib (cp not whitelisted) yields a trailer-stripped
#      keyless container (gate_passthrough_cipher=1): no plaintext escapes
#   7. a NON-whitelisted process (/bin/echo) with the global LD_PRELOAD set runs
#      fine — the plaintext preload + its dep load ungated (why they MUST be
#      plaintext); and the FAILURE MODE: an *encrypted* preload breaks it
#
# Requires root (insmod/mount).  Run:  sudo bash test_proj_setup.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KMOD="$HERE/.."
ROOT="$KMOD/.."
MOD="$KMOD/module/vcachefs.ko"
PACK="$KMOD/tools/vcache-pack.py"
MOUNTRW="$KMOD/tools/vcache-mount-rw"
PROTECT="$ROOT/encryptor/protect.py"

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_proj.XXXXXX)"
INSTALL="$WORK/install"          # plaintext source tree (the unprotected ~/proj)
ENCROOT="$WORK/proj_protect"     # ciphertext lower tree (packer output)
PROJ="$WORK/proj"                # live mountpoints (what the app sees)
AUTHZ="$WORK/authorized_apps.txt"
SBIN="$WORK/state-bin"; SLIB="$WORK/state-lib"

cleanup() {
	"$MOUNTRW" --down --state "$SBIN" "$PROJ/bin" >/dev/null 2>&1
	"$MOUNTRW" --down --state "$SLIB" "$PROJ/lib" >/dev/null 2>&1
	rmmod vcachefs 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$INSTALL/bin/module_x" \
         "$INSTALL/lib/link/module_x" \
         "$INSTALL/lib/link/sw" \
         "$INSTALL/lib/link/3rd" \
         "$PROJ/bin" "$PROJ/lib"

echo "== build the business artifacts =="
# business lib: provides biz_answer()
cat > "$WORK/libxxx.c" <<'EOF'
int biz_answer(void){ return 42; }
EOF
gcc -shared -fPIC -Wl,-soname,libxxx.so \
	-o "$INSTALL/lib/link/module_x/libxxx.so" "$WORK/libxxx.c"
cp "$INSTALL/lib/link/module_x/libxxx.so" "$WORK/libxxx.plain.so"

# third-party lib pulled in by the preload
cat > "$WORK/libfoo.c" <<'EOF'
int foo_marker(void){ return 7; }
EOF
gcc -shared -fPIC -Wl,-soname,libFoo.so \
	-o "$INSTALL/lib/link/3rd/libFoo.so" "$WORK/libfoo.c"

# global LD_PRELOAD shim: "empty" but DT_NEEDED -> libFoo.so (forced via ctor).
# The ctor records into $PRELOAD_MARKER (if set) so a test can OBSERVE whether
# the preload actually loaded — failed LD_PRELOADs are non-fatal in glibc, so
# "did the constructor run / did libFoo resolve" is the real signal, not a crash.
cat > "$WORK/libpreload.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
extern int foo_marker(void);
__attribute__((constructor)) static void init(void){
	const char *m = getenv("PRELOAD_MARKER");
	if (m) { FILE *f = fopen(m, "a"); if (f) { fprintf(f, "preload+foo=%d\n", foo_marker()); fclose(f); } }
}
EOF
gcc -shared -fPIC -Wl,-soname,libPreload.so \
	-o "$INSTALL/lib/link/sw/libPreload.so" "$WORK/libpreload.c" \
	-L"$INSTALL/lib/link/3rd" -lFoo -Wl,--no-as-needed

# an ENCRYPTED preload (NOT blacklisted) used only to demonstrate the failure
# mode in check 7 — an encrypted global preload is silently skipped for every
# non-whitelisted heir (its constructor never runs).
gcc -shared -fPIC -Wl,-soname,libPreloadEnc.so \
	-o "$INSTALL/lib/link/sw/libPreloadEnc.so" "$WORK/libpreload.c" \
	-L"$INSTALL/lib/link/3rd" -lFoo -Wl,--no-as-needed

# child executable: links libxxx (DT_NEEDED), writes a lock next to its binary,
# prints CHILD_OK:<biz_answer>
cat > "$WORK/executable_x.c" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern int biz_answer(void);
int main(int argc, char **argv){
	char dir[1024]; snprintf(dir, sizeof dir, "%s", argv[0]);
	char *sl = strrchr(dir, '/'); if (sl) *sl = 0; else strcpy(dir, ".");
	char lock[1200]; snprintf(lock, sizeof lock, "%s/executable_x.lock", dir);
	FILE *f = fopen(lock, "w");
	if (f) { fprintf(f, "pid=%d arg=%s\n", getpid(), argc>1?argv[1]:""); fclose(f); }
	printf("CHILD_OK:%d arg=%s lock=%s\n", biz_answer(),
	       argc>1?argv[1]:"", f?"written":"FAILED");
	return 0;
}
EOF
gcc -o "$INSTALL/bin/module_x/executable_x" "$WORK/executable_x.c" \
	-L"$INSTALL/lib/link/module_x" -lxxx

# process manager: loads its own encrypted lib, then fork/execs the child by
# RELATIVE path (mimicking boost::process::child with cwd=proj), arg "name,1"
cat > "$WORK/procmgr.c" <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
extern int biz_answer(void);
int main(void){
	printf("PM_LIB_OK:%d\n", biz_answer());   /* procmgr's own encrypted-lib load */
	fflush(stdout);
	pid_t p = fork();
	if (p == 0) {
		char *args[] = { "bin/module_x/executable_x", "executable_x,1", 0 };
		execv("bin/module_x/executable_x", args);   /* relative to cwd */
		perror("execv"); _exit(127);
	}
	int st = 0; waitpid(p, &st, 0);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0) { printf("PM_OK\n"); return 0; }
	printf("PM_CHILD_FAIL:%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	return 1;
}
EOF
gcc -o "$INSTALL/bin/module_x/procmgr" "$WORK/procmgr.c" \
	-L"$INSTALL/lib/link/module_x" -lxxx

# data files (mirrored plaintext under passdata)
printf 'executable_x,1\n' > "$INSTALL/procmgr.conf"

echo "== pack (vcache-pack.py) with the reference blacklist =="
cat > "$WORK/proj-pack.yaml" <<EOF
install_dir: $INSTALL
output_dir:  $ENCROOT
key:         proj.key.hex
mirror_plaintext: true
blacklist:
  - lib/link/3rd/
  - libPreload.so
EOF
python3 "$PACK" "$WORK/proj-pack.yaml" >/dev/null || { echo "pack failed"; exit 1; }

echo "== 1. packer classification + on-disk magic =="
man_ok=1
python3 - "$WORK/vcache-fs-manifest.json" <<'PY' || man_ok=0
import json,sys
m=json.load(open(sys.argv[1]))
enc=set(m["encrypted"]); pln=set(m["plaintext"])
need_enc={"bin/module_x/procmgr","bin/module_x/executable_x",
          "lib/link/module_x/libxxx.so","lib/link/sw/libPreloadEnc.so"}
need_pln={"lib/link/sw/libPreload.so","lib/link/3rd/libFoo.so"}
assert need_enc<=enc, f"missing encrypted: {need_enc-enc}"
assert need_pln<=pln, f"missing plaintext: {need_pln-pln}"
PY
[[ $man_ok -eq 1 ]] && ok "1a. manifest: business ELFs encrypted, preload+3rd plaintext" \
                     || bad "1a. manifest classification wrong"
hdr(){ [ "$(head -c8 "$1" | xxd -p)" = "a74c2e91d63b085f" ]; }
hdr "$ENCROOT/lib/link/module_x/libxxx.so" && ! hdr "$ENCROOT/lib/link/sw/libPreload.so" \
	&& ! hdr "$ENCROOT/lib/link/3rd/libFoo.so" \
	&& ok "1b. on-disk: libxxx.so ANTREV01; libPreload.so + libFoo.so plaintext" \
	|| bad "1b. on-disk magic classification wrong"

echo "== load module (gate_enforce=1, passthrough-cipher=1) + mount rw views =="
# NOTE: requires a dev-mode build (make AREV_DEV_MODE=1)
insmod "$MOD" gate_enforce=1 gate_passthrough_cipher=1 authz_path="$AUTHZ" \
	|| { echo "insmod failed"; exit 1; }
"$MOUNTRW" --passdata --state "$SLIB" "$ENCROOT/lib" "$PROJ/lib" >/dev/null \
	|| { echo "lib mount failed"; dmesg|tail -5; exit 1; }
"$MOUNTRW" --passdata --state "$SBIN" "$ENCROOT/bin" "$PROJ/bin" >/dev/null \
	|| { echo "bin mount failed"; dmesg|tail -5; exit 1; }

# the start-script environment: global preload + recursive lib search path
LP="$PROJ/lib/link/sw/libPreload.so"
LLP="$PROJ/lib/link/module_x:$PROJ/lib/link/sw:$PROJ/lib/link/3rd"

run_pm() {  # run the process manager exactly as the start script would
	( cd "$PROJ" && env LD_PRELOAD="$LP" LD_LIBRARY_PATH="$LLP" \
	  ./bin/module_x/procmgr 2>&1 )
}

echo "== 2. end-to-end: relative-path fork/exec chain through overlay+gate =="
printf '%s\n%s\n' "procmgr" "executable_x" > "$AUTHZ"; chmod 0644 "$AUTHZ"
OUT="$(run_pm)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -eq 0 ]] && grep -q "PM_LIB_OK:42" <<<"$OUT" \
   && grep -q "PM_OK" <<<"$OUT" && grep -q "CHILD_OK:42" <<<"$OUT"; then
	ok "2. procmgr + child ran: encrypted-lib loads, exec-load gate fires through overlay, preload+3rd loaded"
else
	bad "2. end-to-end chain failed (rc=$RC) — see output above"
fi

echo "== 3. child's runtime lock write landed in the overlay UPPER, not .enc =="
UPLOCK="$SBIN/upper/module_x/executable_x.lock"
[[ -f "$UPLOCK" ]] && ok "3a. lock file is in the writable overlay upper" \
                   || bad "3a. lock not found in upper ($UPLOCK)"
[[ -e "$ENCROOT/bin/module_x/executable_x.lock" ]] \
	&& bad "3b. lock leaked into the .enc ciphertext tree!" \
	|| ok "3b. .enc ciphertext tree untouched by the runtime write"

echo "== 4. drop executable_x from the allow-list -> its exec-load is DENIED =="
printf '%s\n' "procmgr" > "$AUTHZ"
OUT="$(run_pm)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -ne 0 ]] && grep -q "PM_LIB_OK:42" <<<"$OUT" \
   && ! grep -q "CHILD_OK" <<<"$OUT"; then
	ok "4. procmgr still runs but the child's exec-load is gated/denied (own-basename gate via overlay)"
else
	bad "4. expected child exec-load denial; got rc=$RC"
fi

echo "== 5. drop procmgr from the allow-list -> procmgr can't exec-load =="
printf '%s\n' "executable_x" > "$AUTHZ"
OUT="$(run_pm)"; RC=$?
echo "$OUT" | sed 's/^/    /'
if [[ $RC -ne 0 ]] && ! grep -q "PM_LIB_OK" <<<"$OUT"; then
	ok "5. unlisted procmgr is denied at exec-load (never reaches its lib load)"
else
	bad "5. unlisted procmgr still started (rc=$RC)"
fi

echo "== 6. cp of the encrypted lib (cp not whitelisted) -> keyless container =="
: > "$AUTHZ"   # nobody whitelisted
LEAK="$WORK/leak.so"
cp "$PROJ/lib/link/module_x/libxxx.so" "$LEAK" 2>/dev/null
ENCSZ=$(stat -c%s "$ENCROOT/lib/link/module_x/libxxx.so")
LEAKSZ=$(stat -c%s "$LEAK" 2>/dev/null || echo -1)
if cmp -s "$LEAK" "$WORK/libxxx.plain.so"; then
	bad "6. cp exfiltrated PLAINTEXT through the mount"
elif [ "$(head -c8 "$LEAK" 2>/dev/null | xxd -p)" = "a74c2e91d63b085f" ] && [[ "$LEAKSZ" -eq $((ENCSZ-40)) ]]; then
	ok "6. cp got a trailer-stripped keyless container ($LEAKSZ == enc-40); no plaintext, no key"
else
	bad "6. unexpected cp result (size=$LEAKSZ enc=$ENCSZ)"
fi

echo "== 7. global plaintext preload loads into a NON-whitelisted process =="
# /bin/echo is not whitelisted and not on the mount. The preload's constructor
# writes PRELOAD_MARKER iff it actually loaded AND libFoo resolved — that marker,
# not echo's exit code, is the real signal (failed preloads are non-fatal).
: > "$AUTHZ"   # nobody whitelisted
M1="$WORK/marker_plain"
env LD_PRELOAD="$LP" LD_LIBRARY_PATH="$LLP" PRELOAD_MARKER="$M1" /bin/echo x >/dev/null 2>&1
if grep -q "preload+foo=7" "$M1" 2>/dev/null; then
	ok "7a. plaintext preload + its 3rd-party dep loaded ungated into an unlisted process (why they MUST be plaintext)"
else
	bad "7a. plaintext preload did not load for an unlisted process"
fi
# FAILURE MODE the blacklist prevents: an ENCRYPTED global preload is denied to
# the unlisted heir, so its constructor never runs (silently skipped) -> no marker.
LPE="$PROJ/lib/link/sw/libPreloadEnc.so"
M2="$WORK/marker_enc"
env LD_PRELOAD="$LPE" LD_LIBRARY_PATH="$LLP" PRELOAD_MARKER="$M2" /bin/echo x >/dev/null 2>&1
if ! grep -q "preload+foo" "$M2" 2>/dev/null; then
	ok "7b. an ENCRYPTED global preload is gated out of the unlisted heir — constructor never runs (the failure mode the blacklist prevents)"
else
	bad "7b. encrypted preload unexpectedly loaded for an unlisted process"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
