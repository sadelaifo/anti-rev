#!/bin/bash
# test_pack_symlinks — antirev-pack.py keeps symlinks resolvable in the
# output tree.  Regression for: symlinks whose target is a filtered-out
# (non-ELF, not in copy:) file dangled, and absolute in-tree targets
# pointed back at the plaintext origin.
#
# Usage: run_test.sh <stub>
set -u
STUB="$1"
PACK="$(dirname "$0")/../../encryptor/antirev-pack.py"
TD="$(dirname "$STUB")/pack_symlinks_test"
SRC="$TD/SW_origin"
OUT="$TD/SW_protected"
FAILS=0
chk(){ if [ "$1" = "$2" ]; then echo "  [PASS] $3"; else echo "  [FAIL] $3 (got '$1' want '$2')"; FAILS=$((FAILS+1)); fi; }

rm -rf "$TD"; mkdir -p "$SRC/lib" "$SRC/etc"
cd "$SRC"
printf 'int v(void){return 1;}\n' | gcc -O2 -shared -fPIC -Wl,-soname,libver.so.1 -xc - -o lib/libver.so.1.2.3
ln -s libver.so.1.2.3 lib/libver.so.1          # soname chain (relative)
ln -s libver.so.1     lib/libver.so
echo '{"k":1}' > etc/config.json
ln -s config.json etc/current.json             # -> filtered-out data file
ln -s "$SRC/lib/libver.so.1.2.3" lib/abs.so     # absolute in-tree target

cat > "$TD/pack.yaml" <<EOF
install_dir: $SRC
output_dir:  $OUT
key:         $TD/proj.key
stub:        $STUB
libs: encrypt
EOF

echo "=== test_pack_symlinks ==="
OUTLOG="$TD/pack.log"
python3 "$PACK" --config "$TD/pack.yaml" >"$OUTLOG" 2>&1 || { echo "  [FAIL] pack errored"; cat "$OUTLOG"; exit 1; }

# 1. soname chain resolves to the encrypted lib
[ -e "$OUT/lib/libver.so" ]  && chk ok ok "soname chain libver.so resolves" || chk broken ok "soname chain libver.so resolves"
# 2. data-file symlink resolves (target auto-copied)
[ -e "$OUT/etc/current.json" ] && chk ok ok "current.json -> config.json resolves (auto-copied)" || chk broken ok "current.json resolves"
[ -f "$OUT/etc/config.json" ]  && chk ok ok "config.json target present in output" || chk missing ok "config.json present"
# 3. absolute in-tree link rewritten to RELATIVE (no origin path)
ABS_TGT="$(readlink "$OUT/lib/abs.so")"
case "$ABS_TGT" in
  /*) chk abs rel "abs.so target rewritten to relative (got absolute: $ABS_TGT)";;
  *)  chk rel rel "abs.so target rewritten to relative ($ABS_TGT)";;
esac
[ -e "$OUT/lib/abs.so" ] && chk ok ok "abs.so resolves inside output tree" || chk broken ok "abs.so resolves"
# 4. auto-copy was reported
grep -q "auto-copied" "$OUTLOG" && chk ok ok "auto-copy reported in pack output" || chk no ok "auto-copy reported"

if [ "$FAILS" = 0 ]; then echo "PASS: packed symlinks stay resolvable + self-contained"; exit 0; fi
echo "FAIL: $FAILS symlink check(s) failed"; cat "$OUTLOG"; exit 1
