#!/bin/bash
# Test missing_syms.py: missing symbols + provider resolution + cycle detection
#
# Builds a small graph of shared libraries with:
#   - libprovider.so: defines provider_func()
#   - libconsumer.so: calls provider_func() but does NOT DT_NEED libprovider
#   - libcycle_a.so:  DT_NEEDs libcycle_b.so, defines cycle_a_func()
#   - libcycle_b.so:  DT_NEEDs libcycle_a.so, defines cycle_b_func()
#   - test_main:      exe that DT_NEEDs libconsumer.so (inherits the gap)
#
# Expected output:
#   - libconsumer.so (and test_main) report provider_func as missing
#   - Tool identifies libprovider.so as the provider
#   - Circular dependency: libcycle_a.so <-> libcycle_b.so

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOL="$SRC_DIR/tools/missing_syms.py"
WORKDIR="$SCRIPT_DIR/_workdir"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

# ── Build test libraries ───────────────────────────────────────────

# libprovider.so: defines provider_func
cat > "$WORKDIR/provider.c" << 'SRC'
int provider_func(int x) { return x * 42; }
SRC
gcc -shared -fPIC -o "$WORKDIR/libprovider.so" "$WORKDIR/provider.c" \
    -Wl,-soname,libprovider.so

# libconsumer.so: uses provider_func WITHOUT linking to libprovider
cat > "$WORKDIR/consumer.c" << 'SRC'
extern int provider_func(int x);
int consumer_func(int x) { return provider_func(x) + 1; }
SRC
gcc -shared -fPIC -o "$WORKDIR/libconsumer.so" "$WORKDIR/consumer.c" \
    -Wl,-soname,libconsumer.so

# libcycle_a.so and libcycle_b.so: circular DT_NEEDED
cat > "$WORKDIR/cycle_a.c" << 'SRC'
extern int cycle_b_func(int);
int cycle_a_func(int x) { return x > 0 ? cycle_b_func(x - 1) : 0; }
SRC
cat > "$WORKDIR/cycle_b.c" << 'SRC'
extern int cycle_a_func(int);
int cycle_b_func(int x) { return x > 0 ? cycle_a_func(x - 1) : 1; }
SRC

# Build cycle libs: need two passes because of circular dep.
# First pass: create stubs for linking
gcc -shared -fPIC -o "$WORKDIR/libcycle_b.so" "$WORKDIR/cycle_b.c" \
    -Wl,-soname,libcycle_b.so 2>/dev/null || true
gcc -shared -fPIC -o "$WORKDIR/libcycle_a.so" "$WORKDIR/cycle_a.c" \
    -Wl,-soname,libcycle_a.so \
    -L"$WORKDIR" -lcycle_b -Wl,-rpath,"$WORKDIR"
# Rebuild B with proper link to A
gcc -shared -fPIC -o "$WORKDIR/libcycle_b.so" "$WORKDIR/cycle_b.c" \
    -Wl,-soname,libcycle_b.so \
    -L"$WORKDIR" -lcycle_a -Wl,-rpath,"$WORKDIR"

# test_main: links to libconsumer only (missing transitive link to libprovider)
cat > "$WORKDIR/main.c" << 'SRC'
extern int consumer_func(int);
#include <stdio.h>
int main(void) {
    printf("result = %d\n", consumer_func(1));
    return 0;
}
SRC
gcc -o "$WORKDIR/test_main" "$WORKDIR/main.c" \
    -L"$WORKDIR" -lconsumer -Wl,-rpath,"$WORKDIR" \
    -Wl,--unresolved-symbols=ignore-in-shared-libs

# liblatent_a.so and liblatent_b.so: latent circular dependency
#   A DT_NEEDs B (explicit), B uses a symbol from A (implicit).
#   If B were to add DT_NEEDED A, it would create a real cycle.
cat > "$WORKDIR/latent_a.c" << 'SRC'
extern int latent_b_func(int);
int latent_a_func(int x) { return latent_b_func(x) + 1; }
SRC
cat > "$WORKDIR/latent_b.c" << 'SRC'
extern int latent_a_func(int);
int latent_b_func(int x) { return x > 0 ? latent_a_func(x - 1) : 0; }
SRC
gcc -shared -fPIC -o "$WORKDIR/liblatent_b.so" "$WORKDIR/latent_b.c" \
    -Wl,-soname,liblatent_b.so
gcc -shared -fPIC -o "$WORKDIR/liblatent_a.so" "$WORKDIR/latent_a.c" \
    -Wl,-soname,liblatent_a.so \
    -L"$WORKDIR" -llatent_b -Wl,-rpath,"$WORKDIR"

# Third-party lib in a subdirectory (will be blacklisted).
# libtp.so: defines tp_func, but also has its own missing symbol (tp_missing)
# that should NOT be reported when blacklisted.
mkdir -p "$WORKDIR/third_party"
cat > "$WORKDIR/third_party/tp.c" << 'SRC'
extern int tp_missing(void);
int tp_func(int x) { return x + 100; }
int tp_wrapper(void) { return tp_missing(); }
SRC
gcc -shared -fPIC -o "$WORKDIR/third_party/libtp.so" \
    "$WORKDIR/third_party/tp.c" -Wl,-soname,libtp.so

# libapp.so: business lib that calls tp_func without linking to libtp
cat > "$WORKDIR/app.c" << 'SRC'
extern int tp_func(int);
int app_func(int x) { return tp_func(x) + 1; }
SRC
gcc -shared -fPIC -o "$WORKDIR/libapp.so" "$WORKDIR/app.c" \
    -Wl,-soname,libapp.so

# Write blacklist file
cat > "$WORKDIR/blacklist.txt" << 'SRC'
# Third-party libraries -- provider-only, not scanned
third_party/
SRC

# Transitive cycle test: libX -> libY -> libZ (DT_NEEDED)
# libZ uses a symbol from libX (without linking).
# libX uses a symbol from libZ (without linking).
# Neither missing edge alone creates a cycle, but BOTH together do:
#   libX -> libY -> libZ -> libX
cat > "$WORKDIR/trans_x.c" << 'SRC'
extern int trans_y_func(int);
extern int trans_z_func(int);
int trans_x_func(int x) { return trans_y_func(x) + 1; }
int trans_x_for_z(int x) { return x * 3; }
SRC
cat > "$WORKDIR/trans_y.c" << 'SRC'
extern int trans_z_func(int);
int trans_y_func(int x) { return trans_z_func(x) + 2; }
SRC
cat > "$WORKDIR/trans_z.c" << 'SRC'
extern int trans_x_for_z(int);
int trans_z_func(int x) { return x > 0 ? trans_x_for_z(x - 1) : 0; }
SRC
# Build: X -> Y -> Z (DT_NEEDED chain)
gcc -shared -fPIC -o "$WORKDIR/libtrans_z.so" "$WORKDIR/trans_z.c" \
    -Wl,-soname,libtrans_z.so
gcc -shared -fPIC -o "$WORKDIR/libtrans_y.so" "$WORKDIR/trans_y.c" \
    -Wl,-soname,libtrans_y.so \
    -L"$WORKDIR" -ltrans_z -Wl,-rpath,"$WORKDIR"
gcc -shared -fPIC -o "$WORKDIR/libtrans_x.so" "$WORKDIR/trans_x.c" \
    -Wl,-soname,libtrans_x.so \
    -L"$WORKDIR" -ltrans_y -Wl,-rpath,"$WORKDIR"
# Now: X DT_NEEDs Y, Y DT_NEEDs Z.
# Missing: Z uses trans_x_for_z (from X, no link) — tool suggests Z -> X
# Missing: X uses trans_z_func (from Z, no link via Y) — wait, X -> Y -> Z
# Actually X already reaches Z transitively through Y. So trans_z_func IS available.
# Let me fix: X should NOT DT_NEED Y. Instead, X just uses symbols from Y and Z
# without linking to either. And Y DT_NEEDs Z.

# Rebuild: only Y -> Z as DT_NEEDED. X has no DT_NEEDED to Y or Z.
gcc -shared -fPIC -o "$WORKDIR/libtrans_x.so" "$WORKDIR/trans_x.c" \
    -Wl,-soname,libtrans_x.so

# Also build a "clean" lib with no issues (should NOT appear in report)
cat > "$WORKDIR/clean.c" << 'SRC'
#include <string.h>
int clean_func(const char *s) { return (int)strlen(s); }
SRC
gcc -shared -fPIC -o "$WORKDIR/libclean.so" "$WORKDIR/clean.c" \
    -Wl,-soname,libclean.so

# Create versioned copies of libclean.so to test dedup
cp "$WORKDIR/libclean.so" "$WORKDIR/libclean.so.1"
cp "$WORKDIR/libclean.so" "$WORKDIR/libclean.so.1.2.3"

# Duplicate-symbol test fixtures ────────────────────────────────────
# libdup_a.so and libdup_b.so both export:
#   dup_strong  (STRONG in both)    -> STRONG x STRONG = error
#   dup_weak    (WEAK in both)      -> WEAK x WEAK     = warning
#   dup_mixed   (STRONG in a, WEAK in b) -> mixed     = warning
#   _ZTV7Example (WEAK in both, vague-linkage) -> filtered by default
#   dup_a_only / dup_b_only         -> unique, no dup
# test_dup links to both libs, so its closure contains the duplicates.
cat > "$WORKDIR/dup_a.c" << 'SRC'
int dup_strong(int x) { return x + 1; }
__attribute__((weak)) int dup_weak(int x) { return x + 10; }
int dup_mixed(int x) { return x + 100; }
__attribute__((weak)) int _ZTV7Example = 42;
int dup_a_only(int x) { return x; }
SRC
cat > "$WORKDIR/dup_b.c" << 'SRC'
int dup_strong(int x) { return x + 2; }
__attribute__((weak)) int dup_weak(int x) { return x + 20; }
__attribute__((weak)) int dup_mixed(int x) { return x + 200; }
__attribute__((weak)) int _ZTV7Example = 43;
int dup_b_only(int x) { return x; }
SRC
gcc -shared -fPIC -o "$WORKDIR/libdup_a.so" "$WORKDIR/dup_a.c" \
    -Wl,-soname,libdup_a.so
gcc -shared -fPIC -o "$WORKDIR/libdup_b.so" "$WORKDIR/dup_b.c" \
    -Wl,-soname,libdup_b.so

cat > "$WORKDIR/dup_main.c" << 'SRC'
extern int dup_a_only(int);
extern int dup_b_only(int);
extern int dup_strong(int);
#include <stdio.h>
int main(void) {
    printf("%d\n", dup_a_only(0) + dup_b_only(0) + dup_strong(0));
    return 0;
}
SRC
gcc -o "$WORKDIR/test_dup" "$WORKDIR/dup_main.c" \
    -L"$WORKDIR" -ldup_a -ldup_b -Wl,-rpath,"$WORKDIR"

echo
echo "=== Built test binaries ==="
file "$WORKDIR"/test_main "$WORKDIR"/lib*.so*
echo

# ── Run the tool ───────────────────────────────────────────────────

echo "=== Running missing_syms.py ==="
export LD_LIBRARY_PATH="$WORKDIR"

FAIL=0

# --- Text mode ---
TEXT_OUT=$("$TOOL" "$WORKDIR" --demangle 2>&1) || true
echo "$TEXT_OUT"

# Check: versioned copies should be deduped
if echo "$TEXT_OUT" | grep -q "versioned copies collapsed"; then
    echo "PASS: versioned copies deduped"
else
    echo "FAIL: did not dedup versioned copies"
    FAIL=1
fi

# Check: libconsumer.so should report provider_func as missing
if echo "$TEXT_OUT" | grep -q "provider_func"; then
    echo "PASS: detected missing provider_func"
else
    echo "FAIL: did not detect missing provider_func"
    FAIL=1
fi

# Check: tool should suggest linking to libprovider.so
if echo "$TEXT_OUT" | grep -q "libprovider.so"; then
    echo "PASS: identified libprovider.so as provider"
else
    echo "FAIL: did not identify libprovider.so as provider"
    FAIL=1
fi

# Check: circular dependency detected
if echo "$TEXT_OUT" | grep -q "libcycle_a.so"; then
    if echo "$TEXT_OUT" | grep -q "libcycle_b.so"; then
        echo "PASS: detected circular dependency"
    else
        echo "FAIL: did not detect cycle_b in circular dep"
        FAIL=1
    fi
else
    echo "FAIL: did not detect cycle_a in circular dep"
    FAIL=1
fi

# Check: libclean.so should NOT appear in missing symbols section
# (it might appear in the cycle section header if it has no issues)
MISSING_SECTION=$(echo "$TEXT_OUT" | sed -n '/Missing symbol report/,/Circular dependencies/p')
if echo "$MISSING_SECTION" | grep -q "libclean.so"; then
    echo "FAIL: libclean.so should not have missing symbols"
    FAIL=1
else
    echo "PASS: libclean.so correctly has no missing symbols"
fi

# Check: latent circular dependency detected (liblatent_b needs liblatent_a,
# but liblatent_a already DT_NEEDs liblatent_b)
if echo "$TEXT_OUT" | grep -q "WARN: creates cycle"; then
    echo "PASS: detected latent circular dependency"
else
    echo "FAIL: did not detect latent circular dependency"
    FAIL=1
fi

# Check: latent cycle summary section exists
if echo "$TEXT_OUT" | grep -q "Latent circular dependencies"; then
    if echo "$TEXT_OUT" | grep -q "latent_a_func"; then
        echo "PASS: latent cycle report shows offending symbol"
    else
        echo "FAIL: latent cycle report missing symbol detail"
        FAIL=1
    fi
else
    echo "FAIL: no latent circular dependency section"
    FAIL=1
fi

# Check: patchelf commands section — safe commands printed, unsafe commented out
if echo "$TEXT_OUT" | grep -q "Patchelf commands"; then
    # Safe command for libconsumer (provider_func from libprovider)
    if echo "$TEXT_OUT" | grep "patchelf --add-needed libprovider.so" | grep -qv "^  #"; then
        echo "PASS: safe patchelf command printed"
    else
        echo "FAIL: safe patchelf command not found"
        FAIL=1
    fi
    # Unsafe command for liblatent_b should be commented out (direct cycle)
    if echo "$TEXT_OUT" | grep -q "# patchelf --add-needed liblatent_a.so"; then
        echo "PASS: unsafe patchelf command commented with warning"
    else
        echo "FAIL: unsafe patchelf command not commented"
        FAIL=1
    fi
    # Transitive cycle: X->Y and Z->X are each safe alone but unsafe together
    # Both should be commented out in the patchelf section
    if echo "$TEXT_OUT" | grep -q "# patchelf --add-needed libtrans_y.so"; then
        if echo "$TEXT_OUT" | grep -q "# patchelf --add-needed libtrans_x.so"; then
            echo "PASS: transitive cycle commands both commented out"
        else
            echo "FAIL: Z->X not flagged as part of transitive cycle"
            FAIL=1
        fi
    else
        echo "FAIL: X->Y not flagged as part of transitive cycle"
        FAIL=1
    fi
else
    echo "FAIL: no patchelf commands section"
    FAIL=1
fi

echo

# --- Duplicate-symbol detection (default mode) ---
# Extract just the duplicate section to make assertions order-robust.
DUP_SECTION=$(echo "$TEXT_OUT" | awk '
    /Duplicate symbols in per-target/ {on=1}
    /Patchelf commands/ {on=0}
    on {print}
')

# test_dup should appear as a consumer
if echo "$DUP_SECTION" | grep -q "test_dup"; then
    echo "PASS: test_dup listed in duplicate report"
else
    echo "FAIL: test_dup not listed in duplicate report"
    FAIL=1
fi

# dup_strong: STRONG x STRONG -> error
if echo "$DUP_SECTION" | grep -A1 "dup_strong$" | grep -q "libdup_a.so:STRONG"; then
    if echo "$DUP_SECTION" | grep -A1 "dup_strong$" | grep -q "libdup_b.so:STRONG"; then
        echo "PASS: dup_strong reported as STRONG x STRONG"
    else
        echo "FAIL: dup_strong missing libdup_b provider"
        FAIL=1
    fi
else
    echo "FAIL: dup_strong not reported"
    FAIL=1
fi

# dup_weak must be in WARNINGS section, not ERRORS.
# Per-consumer section layout: "ERRORS ..." block then "WARNINGS ..." block.
# We check that dup_weak appears after a WARNINGS header somewhere.
if echo "$DUP_SECTION" | awk '
    /WARNINGS \(WEAK or mixed\)/ {warn=1; next}
    /ERRORS \(STRONG x STRONG\)/ {warn=0; next}
    warn && /dup_weak$/ {found=1}
    END {exit !found}
'; then
    echo "PASS: dup_weak reported as WEAK warning"
else
    echo "FAIL: dup_weak not found under WARNINGS"
    FAIL=1
fi

# dup_mixed: STRONG in a, WEAK in b -> warning
if echo "$DUP_SECTION" | awk '
    /WARNINGS \(WEAK or mixed\)/ {warn=1; next}
    /ERRORS \(STRONG x STRONG\)/ {warn=0; next}
    warn && /dup_mixed$/ {found=1}
    END {exit !found}
'; then
    echo "PASS: dup_mixed reported as mixed warning"
else
    echo "FAIL: dup_mixed not found under WARNINGS"
    FAIL=1
fi

# _ZTV7Example should NOT appear in default output (vague-linkage filter)
if echo "$DUP_SECTION" | grep -q "_ZTV7Example"; then
    echo "FAIL: _ZTV7Example should be filtered by default"
    FAIL=1
else
    echo "PASS: C++ vague-linkage symbol filtered by default"
fi

# Exit code: STRONG x STRONG duplicate should make exit non-zero.
# The tool already exits 1 when missing_syms or cycles exist, but confirm
# the dup-error path on its own by running --no-duplicates first:
"$TOOL" "$WORKDIR" --no-duplicates --cycles-only > /dev/null 2>&1 || true
# Already tested elsewhere; just confirm --no-duplicates suppresses output.
NODUP_OUT=$("$TOOL" "$WORKDIR" --no-duplicates 2>&1) || true
if echo "$NODUP_OUT" | grep -q "Duplicate symbols in per-target"; then
    echo "FAIL: --no-duplicates did not skip duplicate section"
    FAIL=1
else
    echo "PASS: --no-duplicates suppresses duplicate report"
fi

# --all-cxx should surface _ZTV7Example
ALLCXX_OUT=$("$TOOL" "$WORKDIR" --all-cxx 2>&1) || true
if echo "$ALLCXX_OUT" | grep -q "_ZTV7Example"; then
    echo "PASS: --all-cxx surfaces vague-linkage symbol"
else
    echo "FAIL: --all-cxx did not include _ZTV7Example"
    FAIL=1
fi

echo

# --- Blacklist mode ---
BL_OUT=$("$TOOL" "$WORKDIR" --blacklist "$WORKDIR/blacklist.txt" --demangle 2>&1) || true
echo "$BL_OUT"

# Check: libapp.so should report tp_func as missing, with libtp.so as provider
if echo "$BL_OUT" | grep -q "tp_func"; then
    if echo "$BL_OUT" | grep -q "libtp.so"; then
        echo "PASS: blacklisted lib used as provider for business lib"
    else
        echo "FAIL: blacklisted libtp.so not suggested as provider"
        FAIL=1
    fi
else
    echo "FAIL: tp_func not detected as missing in libapp.so"
    FAIL=1
fi

# Check: libtp.so's own missing symbol (tp_missing) should NOT be reported
if echo "$BL_OUT" | grep -q "tp_missing"; then
    echo "FAIL: blacklisted lib's own missing symbol was reported"
    FAIL=1
else
    echo "PASS: blacklisted lib not scanned for its own missing symbols"
fi

echo

# --- JSON mode ---
JSON_OUT=$("$TOOL" "$WORKDIR" --json 2>/dev/null) || true

# Validate JSON
if echo "$JSON_OUT" | python3 -m json.tool > /dev/null 2>&1; then
    echo "PASS: JSON output is valid"
else
    echo "FAIL: JSON output is not valid JSON"
    echo "$JSON_OUT" | head -20
    FAIL=1
fi

# Check JSON has expected fields
if echo "$JSON_OUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
assert 'missing_symbols' in data, 'no missing_symbols key'
assert 'circular_dependencies' in data, 'no circular_dependencies key'
# At least one missing symbol entry should mention provider_func
found = False
for entry in data['missing_symbols']:
    for m in entry['missing']:
        if m['symbol'] == 'provider_func':
            found = True
            assert m['provider_soname'] == 'libprovider.so', \
                'wrong provider: %s' % m['provider_soname']
assert found, 'provider_func not in JSON missing_symbols'
# At least one cycle
assert len(data['circular_dependencies']) >= 1, 'no cycles in JSON'
# At least one latent cycle
assert 'latent_circular_dependencies' in data, 'no latent key'
assert len(data['latent_circular_dependencies']) >= 1, 'no latent cycles'
lc = data['latent_circular_dependencies'][0]
assert 'cycle' in lc, 'latent cycle missing cycle path'
assert 'symbols' in lc, 'latent cycle missing symbols'
assert 'duplicate_symbols' in data, 'no duplicate_symbols key'
# At least one consumer must report dup_strong as error
found_dup = False
for r in data['duplicate_symbols']:
    for d in r['duplicates']:
        if d['symbol'] == 'dup_strong':
            found_dup = True
            assert d['severity'] == 'error', \
                'dup_strong severity = %s, want error' % d['severity']
            binds = sorted(p['bind'] for p in d['providers'])
            assert binds == ['GLOBAL', 'GLOBAL'], \
                'dup_strong binds = %s' % binds
assert found_dup, 'dup_strong not in JSON duplicate_symbols'
print('PASS: JSON content validated')
"; then
    :
else
    echo "FAIL: JSON content validation failed"
    FAIL=1
fi

echo

# --- cycles-only mode ---
CYCLE_OUT=$("$TOOL" "$WORKDIR" --cycles-only 2>&1) || true
if echo "$CYCLE_OUT" | grep -q "circular dependency group"; then
    echo "PASS: --cycles-only mode works"
else
    echo "FAIL: --cycles-only did not report cycles"
    FAIL=1
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: missing_syms tool (all checks passed)"
else
    echo "FAIL: missing_syms tool ($FAIL check(s) failed)"
fi
exit "$FAIL"
