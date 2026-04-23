#!/usr/bin/env bash
# query_memory.sh — inspect a process's memory footprint.
#
# Usage:
#   tools/query_memory.sh <PID>
#   tools/query_memory.sh -n <name>      # match by basename (pgrep -f)
#   tools/query_memory.sh -n <name> -w   # watch mode, refresh every 1s
#   tools/query_memory.sh <PID>   -d     # also show per-mapping breakdown
#
# Reports:
#   VmSize / VmPeak  — virtual address space (all allocated), current & peak
#   VmRSS  / VmHWM   — resident physical memory, current & peak
#   VmData           — heap + anon mappings (closest to "what the program itself malloc'd")
#   Pss / Uss        — shared-aware accounting (from smaps_rollup)
#   SysV shm / POSIX shm / memfd — shared-memory segments visible in /proc/<PID>/maps

set -euo pipefail

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

WATCH=0
DETAIL=0
PID=""
NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)  usage 0 ;;
        -n|--name)  NAME="${2:-}"; shift 2 ;;
        -w|--watch) WATCH=1; shift ;;
        -d|--detail) DETAIL=1; shift ;;
        -*)         echo "unknown option: $1" >&2; usage 1 ;;
        *)          PID="$1"; shift ;;
    esac
done

resolve_pid() {
    if [[ -n "$PID" ]]; then
        [[ -d "/proc/$PID" ]] || { echo "no such pid: $PID" >&2; exit 2; }
        echo "$PID"
        return
    fi
    if [[ -n "$NAME" ]]; then
        local pids
        pids=$(pgrep -f -- "$NAME" || true)
        if [[ -z "$pids" ]]; then
            echo "no process matches: $NAME" >&2; exit 2
        fi
        if [[ $(echo "$pids" | wc -l) -gt 1 ]]; then
            echo "multiple matches for '$NAME':" >&2
            ps -o pid,cmd -p $pids >&2
            exit 2
        fi
        echo "$pids"
        return
    fi
    usage 1
}

human() {
    # accepts KiB, prints human-readable
    local kb=$1
    awk -v k="$kb" 'BEGIN{
        if (k+0 == 0) { print "0"; exit }
        split("K M G T", u); s=1
        while (k >= 1024 && s < 4) { k/=1024; s++ }
        printf (s==1 ? "%d %siB" : "%.2f %siB"), k, u[s]
    }'
}

kv_from_status() {
    # $1 = pid, $2 = key (e.g. VmRSS)
    awk -v k="$2:" '$1==k {print $2; exit}' "/proc/$1/status"
}

kv_from_rollup() {
    # $1 = pid, $2 = key (e.g. Pss)
    awk -v k="$2:" '$1==k {print $2; exit}' "/proc/$1/smaps_rollup" 2>/dev/null || true
}

print_report() {
    local pid=$1
    local cmd status_file
    status_file="/proc/$pid/status"
    if [[ ! -r "$status_file" ]]; then
        echo "cannot read $status_file (process gone or no permission)" >&2
        return 1
    fi
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" | sed 's/ *$//')
    [[ -z "$cmd" ]] && cmd=$(kv_from_status "$pid" Name)

    local vmsize vmpeak vmrss vmhwm vmdata vmswap
    vmsize=$(kv_from_status "$pid" VmSize)
    vmpeak=$(kv_from_status "$pid" VmPeak)
    vmrss=$(kv_from_status  "$pid" VmRSS)
    vmhwm=$(kv_from_status  "$pid" VmHWM)
    vmdata=$(kv_from_status "$pid" VmData)
    vmswap=$(kv_from_status "$pid" VmSwap)

    local pss uss priv_clean priv_dirty
    pss=$(kv_from_rollup "$pid" Pss)
    priv_clean=$(kv_from_rollup "$pid" Private_Clean)
    priv_dirty=$(kv_from_rollup "$pid" Private_Dirty)
    if [[ -n "$priv_clean" && -n "$priv_dirty" ]]; then
        uss=$(( priv_clean + priv_dirty ))
    fi

    printf '=== PID %s  (%s) ===\n' "$pid" "$cmd"
    printf '%-10s %12s   %s\n' "Field" "Value" "Meaning"
    printf '%-10s %12s   %s\n' "VmSize" "$(human "${vmsize:-0}")" "virtual address space (current)"
    printf '%-10s %12s   %s\n' "VmPeak" "$(human "${vmpeak:-0}")" "virtual address space (peak)"
    printf '%-10s %12s   %s\n' "VmRSS"  "$(human "${vmrss:-0}")"  "resident physical memory (current)"
    printf '%-10s %12s   %s\n' "VmHWM"  "$(human "${vmhwm:-0}")"  "resident physical memory (peak)"
    printf '%-10s %12s   %s\n' "VmData" "$(human "${vmdata:-0}")" "heap + anon (program-allocated)"
    printf '%-10s %12s   %s\n' "VmSwap" "$(human "${vmswap:-0}")" "swapped out"
    [[ -n "$pss" ]] && printf '%-10s %12s   %s\n' "Pss" "$(human "$pss")" "shared memory apportioned by ref count"
    [[ -n "${uss:-}" ]] && printf '%-10s %12s   %s\n' "Uss" "$(human "$uss")" "strictly private (would free on exit)"

    # shared-memory segments visible in the process
    local maps="/proc/$pid/maps"
    if [[ -r "$maps" ]]; then
        local shm_lines
        shm_lines=$(grep -E 'SYSV|/dev/shm|/memfd:' "$maps" || true)
        if [[ -n "$shm_lines" ]]; then
            echo
            echo "Shared-memory / memfd mappings:"
            echo "$shm_lines" | awk '
                {
                    split($1, r, "-")
                    sz = strtonum("0x" r[2]) - strtonum("0x" r[1])
                    name = ""
                    for (i=6; i<=NF; i++) name = name " " $i
                    key = name
                    sum[key] += sz
                    count[key]++
                }
                END {
                    for (k in sum) {
                        kb = sum[k] / 1024
                        printf "  %-50s  %d map(s), %d KiB\n", k, count[k], kb
                    }
                }' | sort
        fi
    fi

    # optional per-mapping breakdown
    if [[ "$DETAIL" == "1" ]] && command -v pmap >/dev/null; then
        echo
        echo "Top 15 mappings by RSS (pmap -x):"
        pmap -x "$pid" | awk 'NR>2 && $1!="total" {print}' \
            | sort -k3 -n -r | head -15
    fi
}

main() {
    local pid
    pid=$(resolve_pid)

    if [[ "$WATCH" == "1" ]]; then
        while :; do
            clear
            print_report "$pid" || exit 0
            sleep 1
        done
    else
        print_report "$pid"
    fi
}

main "$@"
