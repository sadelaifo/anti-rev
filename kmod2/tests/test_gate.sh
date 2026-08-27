#!/bin/bash
# Step-1 gating test for antirevfs: per-process decrypt authorization by an
# allow-list of executable paths (gate.c).  Demonstrates the *design* is correct
# end to end:
#   1. an authorized program (its exe path is in the allow-list) reads decrypted
#      content through the mount                                     (allow)
#   2. `cp`/`cat` (exe not listed) get -EACCES — cannot exfiltrate plaintext (deny)
#   3. a byte-identical loader NOT in the list is also denied -> it's the
#      *identity* that gates, not the action                        (identity)
#   4. an authorized program that fork+exec's `cp` still can't copy: the child's
#      execve drops authorization (current->mm->exe_file changes)   (lifecycle)
#   5. with gate_enforce=0, `cp` succeeds and yields plaintext -> proves the gate
#      is what's enforcing, not some unrelated failure              (control)
#   6. the lower .enc file is always ciphertext                     (sanity)
#
# Requires root (insmod/mount).  Run:  sudo bash test_gate.sh
set -uo pipefail

# Share one real session keyring across keyctl + mount (see test_antirevfs.sh).
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
PARAM=/sys/module/vcachefs/parameters/gate_enforce

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_gate.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"; AUTHZ="$WORK/authorized_apps.txt"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod vcachefs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build test artifacts =="
cat > "$WORK/libtest.c" <<'EOF'
int antirevfs_answer(void) { return 42; }
EOF
gcc -shared -fPIC -o "$WORK/libtest.so" "$WORK/libtest.c"
cp "$WORK/libtest.so" "$WORK/libtest.plain.so"   # reference plaintext

python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" \
	--libs "$WORK/libtest.so" --output-dir "$ENC" >/dev/null

# An authorized loader (dlopen+dlsym+call) and a byte-identical unlisted twin.
cat > "$WORK/loader.c" <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
	int (*f)(void) = dlsym(h, "antirevfs_answer");
	if (!f) { fprintf(stderr, "dlsym fail\n"); return 3; }
	printf("answer=%d\n", f());
	return f() == 42 ? 0 : 4;
}
EOF
gcc -o "$WORK/loader"      "$WORK/loader.c" -ldl
cp "$WORK/loader" "$WORK/loader_evil"             # identical bytes, NOT listed

# An authorized program that shells out to cp (to test the execve lifecycle).
cat > "$WORK/forkcopy.c" <<'EOF'
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
	char cmd[1024];
	snprintf(cmd, sizeof cmd, "cp '%s' '%s'", argv[1], argv[2]);
	int rc = system(cmd);   /* the cp child's exe is /bin/cp, not authorized */
	if (rc == -1) return 2;
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : 3;  /* propagate cp's real exit code */
}
EOF
gcc -o "$WORK/forkcopy" "$WORK/forkcopy.c"

# Allow-list: only the two authorized programs (full paths).  loader_evil and
# the system cp/cat are deliberately absent.
cat > "$AUTHZ" <<EOF
# antirevfs step-1 allow-list (exe paths or bare basenames)
$WORK/loader
$WORK/forkcopy
EOF
chmod 0644 "$AUTHZ"

echo "== load module (gate_enforce=1) + key + mount =="
# NOTE: requires a dev-mode build (make AREV_DEV_MODE=1)
insmod "$MOD" gate_enforce=1 authz_path="$AUTHZ" || { echo "insmod failed"; exit 1; }
mount -t vcachefs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (gating enforced)" || bad "mount missing"

echo "== 1. authorized program may read decrypted content =="
OUT="$("$WORK/loader" "$MP/libtest.so" 2>&1)"; RC=$?
echo "    loader: $OUT (rc=$RC)"
[[ $RC -eq 0 ]] && ok "authorized loader dlopen'd + called (answer=42)" \
	|| bad "authorized loader failed (rc=$RC)"

echo "== 2. cp / cat (unlisted) are denied =="
if cp "$MP/libtest.so" "$WORK/out_cp" 2>"$WORK/cp.err"; then
	bad "cp of mount succeeded (gate broken)"; cmp -s "$WORK/out_cp" "$WORK/libtest.plain.so" && echo "    -> and it was PLAINTEXT"
else
	grep -qi "permission denied" "$WORK/cp.err" \
		&& ok "cp denied with EACCES (no plaintext exfiltration)" \
		|| { ok "cp denied"; echo "    ($(cat "$WORK/cp.err"))"; }
fi
cat "$MP/libtest.so" >/dev/null 2>&1 && bad "cat of mount succeeded" || ok "cat denied"

echo "== 3. identity, not action: unlisted twin loader is denied =="
OUT="$("$WORK/loader_evil" "$MP/libtest.so" 2>&1)"; RC=$?
echo "    loader_evil: $OUT (rc=$RC)"
[[ $RC -ne 0 ]] && echo "$OUT" | grep -qi "denied\|dlopen" \
	&& ok "byte-identical-but-unlisted loader denied (gates on exe identity)" \
	|| bad "unlisted twin loader was allowed (gate keys on the wrong thing)"

echo "== 4. execve lifecycle: authorized parent, cp child still denied =="
# forkcopy IS authorized, but the cp it exec's is not -> child drops authz.
# Check the ARTIFACT (did plaintext actually escape?), not the child's exit
# code: system() returns a wait-status, so an exit-code check is unreliable.
rm -f "$WORK/out_fork"
"$WORK/forkcopy" "$MP/libtest.so" "$WORK/out_fork" 2>/dev/null
if [[ -s "$WORK/out_fork" ]] && cmp -s "$WORK/out_fork" "$WORK/libtest.plain.so"; then
	bad "fork+exec cp copied PLAINTEXT (lifecycle broken)"
else
	ok "cp child got no plaintext though parent authorized (execve drops authz)"
fi

echo "== 4b. encrypted executable: listed exe runs, cp of it denied =="
# An exec-load is gated on the program's OWN path (at exec-open
# current->mm->exe_file is still the shell), so a *listed* encrypted binary must
# run, while cp of the same file stays denied.
cat > "$WORK/Foo.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("FOO_RAN_OK\n"); return 0; }
EOF
gcc -o "$WORK/Foo" "$WORK/Foo.c"
python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" --libs "$WORK/Foo" --output-dir "$ENC" >/dev/null
chmod +x "$ENC/Foo"                        # mount mirrors the lower mode; exe needs +x
echo "$MP/Foo" >> "$AUTHZ"                  # authorize the exe by its mounted path
OUT="$("$MP/Foo" 2>&1)"; RC=$?
echo "    run: $OUT (rc=$RC)"
[[ "$OUT" == *FOO_RAN_OK* ]] \
	&& ok "listed encrypted exe executes (exec-load gated on file path)" \
	|| bad "listed encrypted exe failed to run: $OUT (rc=$RC)"
cp "$MP/Foo" "$WORK/foo_leak" 2>/dev/null \
	&& bad "cp of encrypted exe succeeded (should be denied)" \
	|| ok "cp of encrypted exe denied"

echo "== 5. control: gate_enforce=0 lets cp through (and it's plaintext) =="
echo 0 > "$PARAM"
if cp "$MP/libtest.so" "$WORK/out_off" 2>/dev/null && cmp -s "$WORK/out_off" "$WORK/libtest.plain.so"; then
	ok "with gating off, cp yields plaintext -> the gate was the enforcer"
else
	bad "gate-off cp did not yield plaintext (test setup issue?)"
fi
echo 1 > "$PARAM"
cp "$MP/libtest.so" "$WORK/out_reon" 2>/dev/null && bad "cp still works after re-enable" || ok "re-enabling gate denies cp again"

echo "== 6. lower .enc file is ciphertext =="
cmp -s "$ENC/libtest.so" "$WORK/libtest.plain.so" && bad "lower file is plaintext!" \
	|| ok "lower .enc file is ciphertext"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
