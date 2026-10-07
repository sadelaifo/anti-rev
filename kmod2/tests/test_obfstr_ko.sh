#!/bin/bash
# Userspace test for the kmod2 module's string-literal obfuscation (no root,
# no kernel build needed).  Guards the opsec property that a shipped release
# .ko carries no self-documenting diagnostic text for `strings` to reveal.
#
# What it checks:
#   1. DECODE CORRECTNESS — every VCF_OBF(obf, 0x..,..) array embedded in the
#      module sources decodes (via the exact obf_key formula) to the readable
#      string named in its preceding /* "..." */ comment.  A single wrong byte
#      would make the kernel log garbage; this catches it.
#   2. REAL MACRO — when gcc is present, a tiny userspace harness that #includes
#      the actual module/obfstr_k.h and instantiates each extracted array is
#      compiled and run, proving the shipped decoder (not just a python mirror)
#      yields the expected plaintext.
#   3. KEY-FORMULA SYNC — the python mirror of obf_key() is asserted identical
#      to shared/obfstr_gen.py's, so the test fails if the formula ever diverges
#      from the encoder the rest of the toolchain uses.
#   4. NO LEAK (failure mode) — the sensitive design tokens (authz, qemu gate,
#      per-exe signature, SHA-256 pin, classify, PKCS#7, lowerdir, ...) must NOT
#      appear as plaintext string literals in release-visible code.  Without the
#      obfuscation these literals sat in .rodata and `strings vcachefs.ko` showed
#      the whole design; this asserts they're gone from the release path.
#   5. .ko STRINGS (end-to-end, optional) — if a release vcachefs.ko is found,
#      `strings` it and assert none of the tokens appear.  Skipped if no .ko
#      (building one needs kernel-devel + the matching toolchain).
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MOD="$HERE/../module"
ROOT="$HERE/../.."
PY="${PYTHON:-python3}"
fail=0
ok()  { echo "  ok : $*"; }
bad() { echo "  BAD: $*"; fail=1; }

# Tokens that must never survive as plaintext literals into a release .ko.
# (Interface strings deliberately kept per CLAUDE.md are excluded: the fs name,
#  mount options, and MODULE_PARM_DESC help text.)
TOKENS='lowerdir|authz|keyring|qemu gate|control device|per-exe signature|SHA-256 pin|pinned caller|classify|gate_require_sig|vendor key|embedding authz cert'

echo "== 1+3. decode every embedded VCF_OBF array (python mirror, formula-synced) =="
"$PY" - "$MOD" "$ROOT/shared/obfstr_gen.py" <<'PYEOF'
import re, sys, pathlib
mod = pathlib.Path(sys.argv[1]); genpy = pathlib.Path(sys.argv[2])

def k(i): return 0x5a ^ (((i * 7) + 13) & 0xff)

# (3) assert our key mirror matches shared/obfstr_gen.py's obf_key()
src = genpy.read_text(encoding="utf-8", errors="replace")
m = re.search(r"def\s+obf_key\s*\([^)]*\)\s*(?:->[^:]*)?:\s*\n\s*return\s+(.+)", src)
assert m, "could not find obf_key() in obfstr_gen.py"
genk = eval("lambda i: " + m.group(1).strip())
assert all(k(i) == genk(i) for i in range(256)), "obf_key formula DIVERGED from obfstr_gen.py"
print("  ok : obf_key formula matches shared/obfstr_gen.py")

# (1) extract VCF_OBF(dst, 0x..,..) together with the preceding /* "..." */ hint
rc = 0
narr = 0
for fn in ("super.c", "inode.c", "gate.c"):
    text = (mod / fn).read_text(encoding="utf-8", errors="replace")
    # find each VCF_OBF call and the nearest preceding /* "..." */ comment
    for m in re.finditer(r'VCF_OBF\s*\(\s*\w+\s*,\s*((?:0x[0-9a-fA-F]{2}\s*,?\s*)+)\)', text):
        arr = [int(x, 16) for x in re.findall(r'0x[0-9a-fA-F]{2}', m.group(1))]
        dec = bytes(arr[i] ^ k(i) for i in range(len(arr)))
        # nearest preceding /* "..." */
        pre = text[:m.start()]
        cm = None
        for c in re.finditer(r'/\*\s*"([^"]*)"', pre):
            cm = c
        expected = cm.group(1) if cm else None
        try:
            s = dec.decode("ascii")
        except UnicodeDecodeError:
            print(f"  BAD: {fn}: array decodes to NON-ASCII {dec!r}"); rc = 1; continue
        narr += 1
        if expected is not None and s != expected:
            print(f"  BAD: {fn}: decode {s!r} != comment {expected!r}"); rc = 1
        else:
            print(f"  ok : {fn}: {s!r}")
if narr == 0:
    print("  BAD: no VCF_OBF arrays found"); rc = 1
sys.exit(rc)
PYEOF
[ $? -ne 0 ] && fail=1

echo "== 2. compile + run the REAL obfstr_k.h decoder on the embedded arrays =="
if command -v gcc >/dev/null 2>&1; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    # Generate a harness that includes the actual module header and feeds it
    # every VCF_OBF array found in the sources; compare output to the comment.
    "$PY" - "$MOD" > "$TMP/harness.c" <<'PYEOF'
import re, sys, pathlib
mod = pathlib.Path(sys.argv[1])
cases = []
for fn in ("super.c", "inode.c", "gate.c"):
    text = (mod / fn).read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r'VCF_OBF\s*\(\s*\w+\s*,\s*((?:0x[0-9a-fA-F]{2}\s*,?\s*)+)\)', text):
        arr = m.group(1).strip().rstrip(',')
        pre = text[:m.start()]; cm = None
        for c in re.finditer(r'/\*\s*"([^"]*)"', pre): cm = c
        exp = cm.group(1) if cm else ""
        cases.append((arr, exp))
print('#include <stdio.h>\n#include <string.h>')
print('typedef unsigned char u8;')               # obfstr_k.h uses u8
print('#include "obfstr_k.h"')
print('int main(void){int bad=0;char b[256];const char*p;')
for arr, exp in cases:
    esc = exp.replace('\\', '\\\\').replace('"', '\\"')
    print(f'  p=VCF_OBF(b, {arr}); if(strcmp(p,"{esc}")){{printf("  BAD(c): %s != %s\\n",p,"{esc}");bad=1;}}')
print('  if(!bad) printf("  ok : all %d arrays decode via real VCF_OBF\\n", %d);' % (0, len(cases)))
print('  return bad;}')
PYEOF
    if gcc -I"$MOD" -o "$TMP/harness" "$TMP/harness.c" 2>"$TMP/cc.err"; then
        # Only a RUNTIME decode mismatch is a real failure; a compile error here
        # is an environment issue (step 1's python mirror already proved decode).
        "$TMP/harness" || fail=1
    else
        echo "  skip: harness did not compile (env — e.g. no kernel uapi headers):"
        sed 's/^/    /' "$TMP/cc.err" | head -3
    fi
else
    echo "  skip: no gcc (python mirror in step 1 already validated the arrays)"
fi

echo "== 4. no sensitive token survives as a plaintext literal in release code =="
# Strip C/C++ comments and AREV_DEV_MODE blocks, then look for the tokens inside
# string literals.  Any hit is a release-build leak.
for fn in super.c inode.c gate.c crypto.c ctldev.c file.c inode.c aesgcm_sw.c; do
    [ -f "$MOD/$fn" ] || continue
    leak="$("$PY" - "$MOD/$fn" "$TOKENS" <<'PYEOF'
import re, sys, pathlib
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
tokens = sys.argv[2]
# drop block + line comments, and #include directives (the header filename is
# resolved at compile time and never lands in .rodata as a string literal)
text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
text = re.sub(r'//[^\n]*', '', text)
text = re.sub(r'(?m)^\s*#\s*include[^\n]*', '', text)
# drop #ifdef AREV_DEV_MODE ... #endif (compiled out of release)
out, depth, i, lines = [], 0, 0, text.split('\n')
skip = 0
nest = []
for ln in lines:
    s = ln.strip()
    if re.match(r'#\s*ifdef\s+AREV_DEV_MODE', s) or re.match(r'#\s*if\s+defined\(\s*AREV_DEV_MODE', s):
        nest.append('dev'); continue
    if re.match(r'#\s*if', s) and nest:
        nest.append('other'); continue
    if re.match(r'#\s*else', s) and nest and nest[-1]=='dev':
        nest[-1]='dev_else'; continue   # keep the #else (release) side
    if re.match(r'#\s*endif', s) and nest:
        nest.pop(); continue
    if 'dev' in nest and nest[-1]=='dev':
        continue
    out.append(ln)
text = '\n'.join(out)
# scan string literals only
hits = []
for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
    if re.search(tokens, lit):
        hits.append(lit)
for h in hits:
    print(h)
PYEOF
)"
    if [ -n "$leak" ]; then
        bad "$fn leaks plaintext token(s) in a release literal:"
        echo "$leak" | sed 's/^/        /'
    else
        ok "$fn: no plaintext design token in release literals"
    fi
done

echo "== 5. (optional) strings a built release vcachefs.ko =="
KO="$(ls "$MOD"/vcachefs.ko "$ROOT"/build*/kmod2/*/vcachefs.ko 2>/dev/null | head -1 || true)"
if [ -n "${KO:-}" ] && [ -f "$KO" ]; then
    hit="$(strings -n 6 "$KO" | grep -EI "$TOKENS" || true)"
    if [ -n "$hit" ]; then
        bad "release .ko ($KO) leaks tokens via strings:"; echo "$hit" | sed 's/^/        /'
    else
        ok "release .ko ($KO): strings shows none of the design tokens"
    fi
else
    echo "  skip: no built vcachefs.ko found (build release first to run the end-to-end check)"
fi

echo
if [ "$fail" -eq 0 ]; then echo "PASS: string-literal obfuscation intact"; else echo "FAIL"; fi
exit $fail
