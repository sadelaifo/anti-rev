#!/usr/bin/env bash
#
# bind_capture.sh — record the *real* symbol bindings glibc performs in
# a plaintext run, then derive the implicit inter-lib dependency edges
# (a bound edge that is NOT already a DT_NEEDED of the consumer).
#
# WHY
#   The daemon/closure cannot statically predict ld.so's runtime
#   resolution. But a plaintext run *is* ground truth: LD_DEBUG=bindings
#   makes glibc print, for every relocation/PLT bind, which object it
#   actually bound to. Recording that and keeping only the edges that
#   are not already explicit DT_NEEDED gives the exact implicit-dep set
#   to feed back in (daemon edge file and/or pack-time patchelf).
#
#   CRUCIAL: each implicit edge is classified by provider —
#     business : provider is under --libs-dir (an encrypted lib; the
#                daemon can pull it into the closure)
#     plaintext: provider is a 3rd-party/system .so NOT under --libs-dir
#                (daemon must force-preload it BY NAME — it never serves
#                 it; this is the Class-3 case)
#     exe      : provider is the main executable itself (already loaded;
#                usually a non-issue, listed for completeness)
#   Without handling the 'plaintext' class, feeding edges to the daemon
#   repeats the old ceiling.
#
# USAGE
#   # 1. record (run the real plaintext workload; exercise dlopen'd
#   #    plugin paths too — only exercised binds are captured):
#   tools/bind_capture.sh run -o /tmp/binddbg -- <business cmd> [args...]
#
#   # 2. analyse (libs-dir = the business shared-lib dir, i.e. the
#   #    set that WILL be encrypted):
#   tools/bind_capture.sh parse /tmp/binddbg --libs-dir /opt/app/lib
#
#   Coverage caveat: only code paths hit in the recorded run produce
#   binds (lazy symbols need to be called, dlopen'd plugins need to be
#   loaded). Run representative workloads; re-record when the business
#   software changes.
#
# Requires: readelf (binutils). Pure read-only analysis.

if [ -z "${BASH_VERSION:-}" ]; then
    if [ -z "${_BIND_CAP_REEXEC:-}" ]; then
        _BIND_CAP_REEXEC=1; export _BIND_CAP_REEXEC
        exec bash "$0" "$@"
    fi
    echo "error: needs real bash. Run: bash $0 ..." >&2; exit 1
fi
set -euo pipefail

sub="${1:-}"; shift || true

if [ "$sub" = "run" ]; then
    out=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -o) out="${2:-}"; shift 2 ;;
            --) shift; break ;;
            *) echo "error: unexpected arg before -- : $1" >&2; exit 2 ;;
        esac
    done
    [ -n "$out" ] || { echo "error: run needs -o OUTDIR -- <cmd>" >&2; exit 2; }
    [ $# -gt 0 ] || { echo "error: no command after --" >&2; exit 2; }
    mkdir -p "$out"
    echo "recording binds -> $out/dbg.<pid>  (cmd: $*)" >&2
    # bindings = the authoritative "bound X to Y" lines.
    LD_DEBUG=bindings LD_DEBUG_OUTPUT="$out/dbg" "$@" || \
        echo "(note: traced command exited non-zero — capture is still usable)" >&2
    n=$(find "$out" -maxdepth 1 -name 'dbg.*' | wc -l)
    echo "done: $n LD_DEBUG file(s) in $out" >&2
    echo "next: tools/bind_capture.sh parse $out --libs-dir <business lib dir>" >&2
    exit 0
fi

if [ "$sub" != "parse" ]; then
    sed -n '2,50p' "$0"; exit 0
fi

OUT="${1:-}"; shift || true
LIBS_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --libs-dir) LIBS_DIR="${2:-}"; shift 2 ;;
        *) echo "error: unknown parse arg: $1" >&2; exit 2 ;;
    esac
done
[ -d "$OUT" ] || { echo "error: not a dir: $OUT" >&2; exit 2; }
command -v readelf >/dev/null 2>&1 || { echo "error: readelf not found" >&2; exit 1; }
if [ -n "$LIBS_DIR" ]; then
    case "$LIBS_DIR" in /*) ;; *) LIBS_DIR="$(cd "$LIBS_DIR" && pwd)" ;; esac
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# Pull "binding file SRC [..] to DST [..]: normal symbol `SYM'" ->  SRC<TAB>DST<TAB>SYM
grep -h 'binding file ' "$OUT"/dbg.* 2>/dev/null \
  | sed -E "s/.*binding file ([^ ]+) \[[0-9]+\] to ([^ ]+) \[[0-9]+\]: (normal|weak) symbol \`([^']+)'.*/\1\t\2\t\4/" \
  | grep -P '\t' > "$tmp/raw" || true

# distinct (src,dst) — we only need the edge, dedup symbols
awk -F'\t' '$1!=$2 {print $1"\t"$2}' "$tmp/raw" | sort -u > "$tmp/edges" || true

# DT_NEEDED cache per src, decide implicit, classify provider
total_edges=0; implicit=0; c_biz=0; c_plain=0; c_exe=0
: > "$tmp/implicit.list"
declare -A NEEDED_CACHE
while IFS=$'\t' read -r src dst; do
    [ -n "$src" ] || continue
    total_edges=$((total_edges+1))
    sb="$(basename -- "$src")"; db="$(basename -- "$dst")"

    key="$src"
    if [ -z "${NEEDED_CACHE[$key]+x}" ]; then
        if [ -f "$src" ]; then
            NEEDED_CACHE[$key]="$(readelf -d "$src" 2>/dev/null \
              | sed -nE 's/.*\(NEEDED\).*\[(.*)\]/\1/p' | tr '\n' '|')"
        else
            NEEDED_CACHE[$key]="|"
        fi
    fi
    needed="|${NEEDED_CACHE[$key]}"

    # already an explicit DT_NEEDED edge? -> not implicit, skip
    case "$needed" in *"|$db|"*) continue ;; esac

    implicit=$((implicit+1))
    # classify provider
    cls="plaintext"
    if [ -n "$LIBS_DIR" ] && case "$dst" in "$LIBS_DIR"/*) true ;; *) false ;; esac; then
        cls="business"; c_biz=$((c_biz+1))
    elif [ "${db%.so}" = "$db" ] && [ "${db##*.so.}" = "$db" ]; then
        cls="exe"; c_exe=$((c_exe+1))           # provider has no .so -> the executable
    else
        c_plain=$((c_plain+1))
    fi
    printf '%s\t%s\t%s\n' "$cls" "$sb" "$db" >> "$tmp/implicit.list"
done < "$tmp/edges"

sort -u "$tmp/implicit.list" -o "$tmp/implicit.list"

echo "=== bind_capture: $OUT ${LIBS_DIR:+(libs-dir=$LIBS_DIR)} ==="
echo "distinct bound inter-object edges : $total_edges"
echo "  already explicit DT_NEEDED      : $((total_edges-implicit))"
echo "  IMPLICIT (no DT_NEEDED edge)    : $implicit"
echo "    provider = business lib       : $c_biz   (daemon CAN pull into closure)"
echo "    provider = plaintext/system   : $c_plain (daemon must force-preload BY NAME — Class-3)"
echo "    provider = the executable     : $c_exe   (already loaded; usually a non-issue)"
echo
if [ "$implicit" -gt 0 ]; then
    echo "--- implicit edges  [class]  consumer  ->  provider ---"
    awk -F'\t' '{printf "  [%-9s] %s  ->  %s\n",$1,$2,$3}' "$tmp/implicit.list"
    echo
    echo "VERDICT: feed the 'business' edges into the daemon closure"
    echo "         graph; the 'plaintext' edges REQUIRE the by-name"
    echo "         force-preload extension (else Class-3 stays broken)."
else
    echo "VERDICT: no implicit edges in this run — either none exist or"
    echo "         the run didn't exercise the paths that trigger them."
fi
