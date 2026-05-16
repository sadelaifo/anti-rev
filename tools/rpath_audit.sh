#!/usr/bin/env bash
#
# rpath_audit.sh — audit (and optionally neutralize) DT_RPATH on a tree
# of shared libs / ELF binaries.
#
# WHY THIS EXISTS
#   antirev's natural-load path resolves encrypted DT_NEEDED deps through
#   a symlink dir placed on LD_LIBRARY_PATH (the symlink points at the
#   *decrypted* memfd).  glibc's library search order is:
#
#       (old-style) DT_RPATH  →  LD_LIBRARY_PATH  →  DT_RUNPATH  →  cache
#
#   So a lib carrying an old-style DT_RPATH that resolves into the
#   on-disk directory (where the *encrypted* ciphertext .so lives — note
#   $ORIGIN resolves to exactly that dir in an antirev deployment) is
#   searched BEFORE LD_LIBRARY_PATH: glibc would load the ciphertext and
#   fail ("invalid ELF") or load garbage.  DT_RUNPATH is searched AFTER
#   LD_LIBRARY_PATH, so the decrypted symlink always wins — RUNPATH is
#   safe, RPATH is the hazard.
#
#   This script first just TELLS YOU whether the hazard exists in your
#   tree (read-only survey, the default).  Only with an explicit --fix
#   does it touch anything, and then it backs every file up first.
#
# USAGE
#   tools/rpath_audit.sh [DIR]                 # survey (read-only, default)
#   tools/rpath_audit.sh [DIR] --fix convert   # DT_RPATH -> DT_RUNPATH (keep paths)
#   tools/rpath_audit.sh [DIR] --fix remove    # drop DT_RPATH entirely
#
#   DIR defaults to the current directory.  Recurses.  Operates on every
#   real ELF (by magic, not extension) — .so, .so.N, .elf, unsuffixed.
#
# NOTES
#   - convert preserves the path list, only flips the tag RPATH->RUNPATH.
#     RUNPATH is NOT transitive (RPATH is): a lib that relied on its
#     RPATH being inherited by its *dependencies'* searches could change
#     behaviour.  The survey shows you exactly which/how many libs carry
#     RPATH so you can judge before converting.
#   - --fix writes "<file>.rpath.bak" next to each modified file and
#     re-verifies the result; it is idempotent and safe to re-run.
#   - Requires readelf (binutils) and, for --fix, patchelf.

set -euo pipefail

# ---- args ---------------------------------------------------------------
DIR="."
FIX=""
MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --fix)
            FIX=1
            MODE="${2:-}"
            shift 2 || { echo "error: --fix needs a mode: convert|remove" >&2; exit 2; }
            ;;
        -h|--help)
            sed -n '2,40p' "$0"; exit 0 ;;
        -*)
            echo "error: unknown option: $1" >&2; exit 2 ;;
        *)
            DIR="$1"; shift ;;
    esac
done

if [ -n "$FIX" ] && [ "$MODE" != "convert" ] && [ "$MODE" != "remove" ]; then
    echo "error: --fix mode must be 'convert' or 'remove' (got '${MODE:-}')" >&2
    exit 2
fi

command -v readelf >/dev/null 2>&1 || { echo "error: readelf not found (install binutils)" >&2; exit 1; }
if [ -n "$FIX" ]; then
    command -v patchelf >/dev/null 2>&1 || { echo "error: patchelf not found (needed for --fix)" >&2; exit 1; }
fi

[ -d "$DIR" ] || { echo "error: not a directory: $DIR" >&2; exit 2; }

# ---- scan ---------------------------------------------------------------
total=0          # ELF files scanned
n_rpath=0        # have DT_RPATH (HAZARD under natural-load)
n_runpath=0      # have DT_RUNPATH only (safe)
n_none=0         # neither (safe)
n_fixed=0
rpath_list=()    # "file\tvalue" for the hazardous ones

is_elf() {
    # first 4 bytes == 0x7f 'E' 'L' 'F'
    [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')" = "7f454c46" ]
}

while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    is_elf "$f" || continue
    total=$((total + 1))

    # readelf -d distinguishes (RPATH) from (RUNPATH); patchelf does not.
    dyn="$(readelf -d "$f" 2>/dev/null || true)"
    rpath_line="$(printf '%s\n' "$dyn" | grep -E '\(RPATH\)'   || true)"
    runpath_line="$(printf '%s\n' "$dyn" | grep -E '\(RUNPATH\)' || true)"

    if [ -n "$rpath_line" ]; then
        n_rpath=$((n_rpath + 1))
        val="$(printf '%s\n' "$rpath_line" | sed -E 's/.*\[(.*)\].*/\1/')"
        # ELF machine, so a mixed x86_64+aarch64 tree audited from one
        # host can be read per target arch (readelf is cross-arch).
        mach="$(readelf -h "$f" 2>/dev/null | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
        [ -n "$mach" ] || mach="?"
        rpath_list+=("$mach"$'\t'"$f"$'\t'"$val")

        if [ -n "$FIX" ]; then
            cp -p -- "$f" "$f.rpath.bak"
            if [ "$MODE" = "remove" ]; then
                patchelf --remove-rpath -- "$f"
            else
                cur="$(patchelf --print-rpath -- "$f" 2>/dev/null || true)"
                patchelf --remove-rpath -- "$f"
                [ -n "$cur" ] && patchelf --set-rpath "$cur" -- "$f"   # writes DT_RUNPATH
            fi
            # verify: no (RPATH) tag must remain
            if readelf -d "$f" 2>/dev/null | grep -qE '\(RPATH\)'; then
                echo "FAIL: DT_RPATH still present after fix: $f" >&2
                exit 1
            fi
            n_fixed=$((n_fixed + 1))
        fi
    elif [ -n "$runpath_line" ]; then
        n_runpath=$((n_runpath + 1))
    else
        n_none=$((n_none + 1))
    fi
done < <(find "$DIR" -type f ! -name '*.rpath.bak' -print0)

# ---- report -------------------------------------------------------------
echo "=== rpath_audit: $DIR ==="
echo "ELF files scanned : $total"
echo "  DT_RPATH (HAZARD): $n_rpath"
echo "  DT_RUNPATH (safe): $n_runpath"
echo "  neither   (safe) : $n_none"
if [ -n "$FIX" ]; then
    echo "  fixed ($MODE)    : $n_fixed   (backups: *.rpath.bak)"
fi

if [ "$n_rpath" -gt 0 ]; then
    echo
    echo "  DT_RPATH by ELF arch (this is what matters per target machine):"
    printf '%s\n' "${rpath_list[@]}" | cut -f1 | sort | uniq -c | sed 's/^/    /'
    echo
    echo "--- libs carrying DT_RPATH (searched BEFORE LD_LIBRARY_PATH ---"
    echo "--- => natural-load could load the ENCRYPTED on-disk copy) ---"
    for e in "${rpath_list[@]}"; do
        IFS=$'\t' read -r _m _f _v <<< "$e"
        printf '  [%s] %s\n      RPATH = %s\n' "$_m" "$_f" "$_v"
    done
fi

echo
if [ "$n_rpath" -eq 0 ]; then
    echo "VERDICT: no DT_RPATH in this tree -> natural-load already loads the"
    echo "         decrypted libs safely here. Pack-time neutralization would"
    echo "         only be a belt-and-suspenders invariant, not a fix you need."
    exit 0
else
    if [ -n "$FIX" ]; then
        echo "VERDICT: $n_fixed lib(s) neutralized ($MODE). Re-run without --fix"
        echo "         to confirm DT_RPATH count is now 0. Test on a COPY of the"
        echo "         tree and run the full regression before trusting it."
    else
        echo "VERDICT: $n_rpath lib(s) carry DT_RPATH -> natural-load is UNSAFE"
        echo "         for them as-is (ciphertext could win the search). Inspect"
        echo "         the list above, then dry-run a fix on a COPY:"
        echo "             cp -a \"$DIR\" /tmp/rpath_test && \\"
        echo "             tools/rpath_audit.sh /tmp/rpath_test --fix convert"
    fi
    exit 0
fi
