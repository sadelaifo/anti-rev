#!/bin/bash
# Whitelist verification for antirevfs gating (gate.c), exercising the exact
# operational contract:
#
#   Given an allow-list at the DOCUMENTED default path /etc/authorized_apps.txt
#   containing several encrypted programs, EVERY listed program must run, while
#   an unlisted ("undocumented") encrypted program must be refused execution,
#   and `cp`/`cat` of any encrypted file must be denied (no plaintext escape).
#
# This complements test_gate.sh, which only runs a single encrypted exe and
# overrides authz_path with a temp file.  Here we use the real default path and
# multiple programs.
#
# Kernel-version note: the only version-sensitive part of this path is exec-load
# detection (arev_is_exec_open in compat.h), which tests BOTH FMODE_EXEC (set at
# ->open on SLES 4.12) and __FMODE_EXEC in f_flags (the 6.8 home).  The whitelist
# matching itself (d_path + authz_list_matches) is version-independent.
#
# Requires root (insmod/mount).  Run:  sudo bash test_gate_whitelist.sh
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
AUTHZ=/etc/authorized_apps.txt          # the documented default path

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[[ $EUID -eq 0 ]] || { echo "must run as root (insmod/mount)"; exit 1; }
[[ -f "$MOD" ]] || { echo "module not built: $MOD (run: make -C $KMOD/module CC=gcc-12)"; exit 1; }

WORK="$(mktemp -d /tmp/antirevfs_wl.XXXXXX)"
ENC="$WORK/.enc/lib"; MP="$WORK/lib"
mkdir -p "$ENC" "$MP"

# Back up any pre-existing /etc/authorized_apps.txt so we leave the box as found.
AUTHZ_BAK=""
if [[ -e "$AUTHZ" ]]; then AUTHZ_BAK="$(mktemp)"; cp -a "$AUTHZ" "$AUTHZ_BAK"; fi

cleanup() {
	mountpoint -q "$MP" && umount "$MP"
	rmmod antirevfs 2>/dev/null
	"$KEYCTL" clear >/dev/null 2>&1
	if [[ -n "$AUTHZ_BAK" ]]; then cp -a "$AUTHZ_BAK" "$AUTHZ"; rm -f "$AUTHZ_BAK";
	else rm -f "$AUTHZ"; fi
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "== build encrypted programs =="
# Three programs that WILL be whitelisted, plus one "undocumented" rogue that
# will NOT be.  Each prints a unique marker so we can prove it actually ran.
WHITELISTED=(alpha beta gamma)
ALL=(alpha beta gamma rogue)
for name in "${ALL[@]}"; do
	cat > "$WORK/$name.c" <<EOF
#include <stdio.h>
int main(void){ printf("RAN_$name\n"); return 0; }
EOF
	gcc -o "$WORK/$name" "$WORK/$name.c"
done
python3 "$PROTECT" encrypt-lib --embed-key --key "$WORK/key.hex" \
	--libs "$WORK/alpha" "$WORK/beta" "$WORK/gamma" "$WORK/rogue" \
	--output-dir "$ENC" >/dev/null
chmod +x "$ENC"/alpha "$ENC"/beta "$ENC"/gamma "$ENC"/rogue   # mount mirrors lower mode

echo "== write /etc/authorized_apps.txt (alpha,beta,gamma; rogue absent) =="
{
	echo "# antirevfs whitelist verification"
	for name in "${WHITELISTED[@]}"; do echo "$MP/$name"; done
} > "$AUTHZ"
chmod 0644 "$AUTHZ"
cat "$AUTHZ" | sed 's/^/    /'

echo "== load module (gate_enforce=1, default authz_path) + key + mount =="
insmod "$MOD" gate_enforce=1 || { echo "insmod failed"; exit 1; }
mount -t antirevfs -o ro "$ENC" "$MP" || { echo "mount failed"; dmesg | tail -5; exit 1; }
mount | grep -q "$MP" && ok "mounted antirevfs (gating enforced)" || bad "mount missing"

echo "== 1. every whitelisted program runs =="
for name in "${WHITELISTED[@]}"; do
	OUT="$("$MP/$name" 2>&1)"; RC=$?
	if [[ $RC -eq 0 && "$OUT" == "RAN_$name" ]]; then
		ok "whitelisted '$name' ran (output: $OUT)"
	else
		bad "whitelisted '$name' failed to run (rc=$RC out='$OUT')"
	fi
done

echo "== 2. undocumented (unlisted) encrypted program is refused execution =="
OUT="$("$MP/rogue" 2>&1)"; RC=$?
if [[ $RC -ne 0 && "$OUT" != "RAN_rogue" ]]; then
	ok "unlisted 'rogue' denied (rc=$RC, msg: ${OUT:-<none>})"
else
	bad "unlisted 'rogue' was allowed to run (rc=$RC out='$OUT') -- gate broken"
fi

echo "== 3. cp of an encrypted program is denied (no plaintext exfiltration) =="
if cp "$MP/alpha" "$WORK/alpha_leak" 2>/dev/null; then
	if cmp -s "$WORK/alpha_leak" "$WORK/alpha"; then
		bad "cp of 'alpha' produced PLAINTEXT (exfiltration!)"
	else
		bad "cp of 'alpha' succeeded (should be denied even if ciphertext)"
	fi
else
	ok "cp of whitelisted-but-encrypted 'alpha' denied"
fi
cp "$MP/rogue" "$WORK/rogue_leak" 2>/dev/null \
	&& bad "cp of 'rogue' succeeded (should be denied)" \
	|| ok "cp of unlisted 'rogue' denied"
cat "$MP/alpha" >/dev/null 2>&1 && bad "cat of 'alpha' succeeded" || ok "cat of 'alpha' denied"

echo "== 4. control: gate_enforce=0 lets cp through as plaintext =="
echo 0 > "$PARAM"
if cp "$MP/alpha" "$WORK/alpha_off" 2>/dev/null && cmp -s "$WORK/alpha_off" "$WORK/alpha"; then
	ok "with gating off, cp yields plaintext -> the gate was the enforcer"
else
	bad "gate-off cp did not yield plaintext (test setup issue?)"
fi
echo 1 > "$PARAM"
"$MP/rogue" >/dev/null 2>&1 && bad "rogue runs after re-enable" || ok "re-enabling gate denies rogue again"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
