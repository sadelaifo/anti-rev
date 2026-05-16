#!/usr/bin/env bash
#
# rpath_audit.sh — audit (and optionally neutralize) DT_RPATH on a tree
# of shared libs / ELF binaries.
#
# WHY THIS EXISTS
#   antirev's natural-load path resolves encrypted DT_NEEDED deps through
#   a symlink dir on LD_LIBRARY_PATH (symlink -> the *decrypted* memfd).
#   glibc's search order is:
#
#       (old-style) DT_RPATH  ->  LD_LIBRARY_PATH  ->  DT_RUNPATH  -> cache
#
#   A lib with an old-style DT_RPATH resolving into the on-disk dir
#   (where the *encrypted* ciphertext .so lives; $ORIGIN resolves to
#   exactly that dir) is searched BEFORE LD_LIBRARY_PATH: glibc loads
#   the ciphertext and fails / loads garbage.  DT_RUNPATH is searched
#   AFTER LD_LIBRARY_PATH, so the decrypted symlink wins -> safe.
#   RPATH = hazard, RUNPATH / none = safe.
#
# USAGE
#   tools/rpath_audit.sh [DIR] [--libs-only] [--fix convert|remove]
#
#   DIR           tree to scan (default: .), recursed
#   --libs-only   only look at *.so / *.so.* / *.elf  (MUCH faster on a
#                 full install tree full of scripts/data; recommended)
#   --fix convert DT_RPATH -> DT_RUNPATH, keep the path list
#   --fix remove  drop DT_RPATH entirely
#   (default = read-only survey; nothing is modified)
#
#   Streams every DT_RPATH hit as it is found and prints a progress
#   counter to stderr, so a big tree shows output immediately.
#
# NOTES
#   - convert preserves paths, only flips the tag. RUNPATH is NOT
#     transitive (RPATH is); the survey lists every affected lib so the
#     blast radius is visible before converting.
#   - --fix writes "<file>.rpath.bak" and re-verifies; idempotent.
#   - Requires readelf; --fix also needs patchelf.

# Re-exec under real bash if started by a POSIX sh (dash / busybox ash):
# uses arrays / here-strings.  POSIX-parseable, runs before any bashism.
if [ -z "${BASH_VERSION:-}" ]; then
    if [ -z "${_RPATH_AUDIT_REEXEC:-}" ]; then
        _RPATH_AUDIT_REEXEC=1
        export _RPATH_AUDIT_REEXEC
        exec bash "$0" "$@"
    fi
    echo "error: needs real bash (got a POSIX sh; 'bash' on PATH is not bash). Run: bash $0 ..." >&2
    exit 1
fi

set -euo pipefail

DIR="."
FIX=""
MODE=""
LIBS_ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --libs-only) LIBS_ONLY=1; shift ;;
        --fix) FIX=1; MODE="${2:-}"; shift 2 || { echo "error: --fix needs convert|remove" >&2; exit 2; } ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        -*) echo "error: unknown option: $1" >&2; exit 2 ;;
        *) DIR="$1"; shift ;;
    esac
done

if [ -n "$FIX" ] && [ "$MODE" != "convert" ] && [ "$MODE" != "remove" ]; then
    echo "error: --fix mode must be 'convert' or 'remove' (got '${MODE:-}')" >&2; exit 2
fi
command -v readelf >/dev/null 2>&1 || { echo "error: readelf not found (install binutils)" >&2; exit 1; }
if [ -n "$FIX" ]; then
    command -v patchelf >/dev/null 2>&1 || { echo "error: patchelf not found (needed for --fix)" >&2; exit 1; }
fi
[ -d "$DIR" ] || { echo "error: not a directory: $DIR" >&2; exit 2; }

total=0; n_rpath=0; n_runpath=0; n_none=0; n_fixed=0
rpath_list=()

# Build the find predicate.  --libs-only skips the (usually huge)
# non-lib file population entirely -> the dominant speedup.
if [ -n "$LIBS_ONLY" ]; then
    find_expr=( -type f ! -name '*.rpath.bak' \( -name '*.so' -o -name '*.so.*' -o -name '*.elf' \) )
else
    find_expr=( -type f ! -name '*.rpath.bak' )
fi

echo "scanning $DIR ${LIBS_ONLY:+(libs-only) }..." >&2

while IFS= read -r -d '' f; do
    # One fork per file: readelf -d.  Non-ELF -> empty stdout (skip,
    # don't count).  Any ELF (even static) -> non-empty -> counted.
    dyn="$(readelf -d "$f" 2>/dev/null || true)"
    [ -n "$dyn" ] || continue
    total=$((total + 1))
    if [ $((total % 500)) -eq 0 ]; then
        printf '\r  scanned %d ELF (rpath hits: %d)   ' "$total" "$n_rpath" >&2
    fi

    # No grep forks: bash substring test on the captured text.
    if [[ "$dyn" == *"(RPATH)"* ]]; then
        n_rpath=$((n_rpath + 1))
        rline=""
        while IFS= read -r ln; do
            case "$ln" in *"(RPATH)"*) rline="$ln"; break ;; esac
        done <<< "$dyn"
        val="${rline##*\[}"; val="${val%%\]*}"
        mach="$(readelf -h "$f" 2>/dev/null | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"
        [ -n "$mach" ] || mach="?"
        rpath_list+=("$mach"$'\t'"$f"$'\t'"$val")
        # stream the hit immediately
        printf '\r\033[K  [%s] %s\n      RPATH = %s\n' "$mach" "$f" "$val" >&2

        if [ -n "$FIX" ]; then
            cp -p -- "$f" "$f.rpath.bak"
            if [ "$MODE" = "remove" ]; then
                patchelf --remove-rpath -- "$f"
            else
                cur="$(patchelf --print-rpath -- "$f" 2>/dev/null || true)"
                patchelf --remove-rpath -- "$f"
                [ -n "$cur" ] && patchelf --set-rpath "$cur" -- "$f"   # -> DT_RUNPATH
            fi
            if readelf -d "$f" 2>/dev/null | grep -qE '\(RPATH\)'; then
                echo "FAIL: DT_RPATH still present after fix: $f" >&2; exit 1
            fi
            n_fixed=$((n_fixed + 1))
        fi
    elif [[ "$dyn" == *"(RUNPATH)"* ]]; then
        n_runpath=$((n_runpath + 1))
    else
        n_none=$((n_none + 1))
    fi
done < <(find "$DIR" "${find_expr[@]}" -print0)

printf '\r\033[K' >&2   # clear the progress line

echo
echo "=== rpath_audit: $DIR ${LIBS_ONLY:+(libs-only)} ==="
echo "ELF scanned       : $total"
echo "  DT_RPATH (HAZARD): $n_rpath"
echo "  DT_RUNPATH (safe): $n_runpath"
echo "  neither   (safe) : $n_none"
[ -n "$FIX" ] && echo "  fixed ($MODE)    : $n_fixed   (backups: *.rpath.bak)"

if [ "$n_rpath" -gt 0 ]; then
    echo
    echo "  DT_RPATH by ELF arch (decide per target machine):"
    printf '%s\n' "${rpath_list[@]}" | cut -f1 | sort | uniq -c | sed 's/^/    /'
fi

echo
if [ "$n_rpath" -eq 0 ]; then
    echo "VERDICT: no DT_RPATH here -> natural-load already loads decrypted"
    echo "         libs safely. Pack-time neutralization would only be a"
    echo "         belt-and-suspenders invariant, not a fix you need."
else
    if [ -n "$FIX" ]; then
        echo "VERDICT: $n_fixed lib(s) neutralized ($MODE). Re-run w/o --fix to"
        echo "         confirm count is 0. Validate on a COPY + full regression."
    else
        echo "VERDICT: $n_rpath lib(s) carry DT_RPATH -> natural-load UNSAFE for"
        echo "         them (ciphertext could win). Look at the arch breakdown"
        echo "         (only the arch you run antirev on matters), then dry-run"
        echo "         a fix on a COPY:  cp -a DIR /tmp/t && \\"
        echo "             tools/rpath_audit.sh /tmp/t --libs-only --fix convert"
    fi
fi
exit 0
