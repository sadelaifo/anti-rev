#!/bin/bash
# Access-control matrix for antirevfs gating (gate.c) — the explicit contract:
#
#   For an ENCRYPTED file under the mount, with gate_enforce=1 and an allow-list
#   naming `listed` but not `unlisted`:
#
#                     EXECUTE            READ (as plaintext)     WRITE
#     listed exe      SUCCESS            denied  (cat/cp)        denied (ro mount)
#     unlisted exe    denied (EACCES)    denied  (cat/cp)        denied (ro mount)
#
#   Plus the cell that makes the gate meaningful: a process *running as* the
#   listed exe SUCCESSFULLY reads an encrypted data file (task-authorized),
#   while `cat` (an unauthorized reader) is denied on the same file.
#
# Notes on semantics (why this isn't just "listed => everything succeeds"):
#   * EXECUTE is the operation keyed on allow-list membership (exec-load gated on
#     the program's OWN path): listed runs, unlisted is refused.
#   * READ as plaintext is gated on the CALLER's exe, so cat/cp/editors are
#     denied for ANY encrypted file regardless of listing — that is the
#     no-exfiltration property. "Read succeeds" only when the *authorized
#     program itself* reads (the last section proves this).
#   * WRITE always fails because the mount is READ-ONLY — independent of the
#     gate (the control section proves writes still fail with gate_enforce=0).
#
# Requires root (insmod/mount).  Run:  sudo bash test_gate_access_matrix.sh
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
MOD="$KMOD/module/antirevfs.ko"
PROTECT="$ROOT/encryptor/protect.py"
KEYCTL="$KMOD/tools/antirev-keyctl"
PARAM=/sys/module/antirevfs/parameters/gate_enforce

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_matrix.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"
mkdir -p "$ENC" "$MP"

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod antirevfs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build encrypted programs + an encrypted data file =="
# `listed` reads the encrypted data file passed in argv[1] and prints its bytes,
# proving an AUTHORIZED process can read encrypted data through the shared cache.
cat > "$WORK/listed.c" <<'EOF'
#include <stdio.h>
int main(int argc, char **argv){
	printf("RAN_listed\n");
	if (argc > 1) {
		FILE *f = fopen(argv[1], "rb");
		if (!f) { printf("READ_FAIL\n"); return 2; }
		char b[64] = {0}; size_t n = fread(b, 1, sizeof b - 1, f); fclose(f);
		printf("READ_OK:%.*s\n", (int)n, b);
	}
	return 0;
}
EOF
cat > "$WORK/unlisted.c" <<'EOF'
#include <stdio.h>
int main(void){ printf("RAN_unlisted\n"); return 0; }
EOF
gcc -o "$WORK/listed"   "$WORK/listed.c"
gcc -o "$WORK/unlisted" "$WORK/unlisted.c"
printf 'TOPSECRET42' > "$WORK/secret.dat"

python3 "$PROTECT" encrypt-lib --key "$WORK/key.hex" \
	--libs "$WORK/listed" "$WORK/unlisted" "$WORK/secret.dat" \
	--output-dir "$ENC" >/dev/null
chmod +x "$ENC/listed" "$ENC/unlisted"          # mount mirrors the lower mode

echo "== allow-list names 'listed' only (unlisted absent) =="
AUTHZ="$WORK/authz.txt"
echo "$MP/listed" > "$AUTHZ"
chmod 0644 "$AUTHZ"
sed 's/^/    /' "$AUTHZ"

echo "== load module (gate_enforce=1, authz_path=$AUTHZ) + key + mount (ro) =="
insmod "$MOD" gate_enforce=1 authz_path="$AUTHZ" || { echo "insmod failed"; exit 1; }
"$KEYCTL" unlock --keyfile "$WORK/key.hex" >/dev/null
mount -t antirevfs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (gating enforced, read-only)" || bad "mount missing"

echo "== EXECUTE: listed succeeds, unlisted denied =="
OUT="$("$MP/listed" "$MP/secret.dat" 2>&1)"; RC=$?
if [[ $RC -eq 0 && "$OUT" == *RAN_listed* ]]; then
	ok "listed exe EXECUTES (rc=0)"
else
	bad "listed exe failed to execute (rc=$RC out='$OUT')"
fi
OUT2="$("$MP/unlisted" 2>&1)"; RC2=$?
if [[ $RC2 -ne 0 && "$OUT2" != *RAN_unlisted* ]]; then
	ok "unlisted exe EXECUTION denied (rc=$RC2)"
else
	bad "unlisted exe executed (rc=$RC2 out='$OUT2') -- gate broken"
fi

echo "== READ as plaintext (cat/cp): denied for BOTH (no exfiltration) =="
for f in listed unlisted secret.dat; do
	cat "$MP/$f" >/dev/null 2>&1 \
		&& bad "cat of '$f' succeeded (exfiltration!)" \
		|| ok "cat of '$f' denied"
done
cp "$MP/listed" "$WORK/leak" 2>/dev/null \
	&& bad "cp of 'listed' succeeded (should be denied)" \
	|| ok "cp of 'listed' denied"

echo "== WRITE: denied for BOTH (read-only mount) =="
for f in listed unlisted secret.dat; do
	if : > "$MP/$f" 2>/dev/null || echo x >> "$MP/$f" 2>/dev/null; then
		bad "write to '$f' succeeded (mount not read-only?)"
	else
		ok "write to '$f' denied (read-only)"
	fi
done

echo "== READ success cell: the AUTHORIZED program reads encrypted data =="
# `listed` is in the allow-list, so when IT opens secret.dat the task gate
# authorizes it and it reads the decrypted bytes — while cat (above) could not.
if [[ "$OUT" == *"READ_OK:TOPSECRET42"* ]]; then
	ok "authorized process read encrypted data (READ_OK:TOPSECRET42)"
else
	bad "authorized process could not read encrypted data (out='$OUT')"
fi

echo "== control: gate_enforce=0 -> execute+read flip; write still denied =="
echo 0 > "$PARAM"
"$MP/unlisted" 2>&1 | grep -q RAN_unlisted \
	&& ok "gate off: unlisted now EXECUTES (gate was the exec enforcer)" \
	|| bad "gate off: unlisted still blocked (setup issue?)"
if cat "$MP/secret.dat" 2>/dev/null | grep -q TOPSECRET42; then
	ok "gate off: cat yields plaintext (gate was the read enforcer)"
else
	bad "gate off: cat did not yield plaintext (setup issue?)"
fi
if : > "$MP/secret.dat" 2>/dev/null; then
	bad "gate off: write succeeded (mount should still be read-only)"
else
	ok "gate off: write STILL denied (read-only is independent of the gate)"
fi
echo 1 > "$PARAM"
"$MP/unlisted" >/dev/null 2>&1 && bad "unlisted runs after re-enable" || ok "re-enabling gate denies unlisted again"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
