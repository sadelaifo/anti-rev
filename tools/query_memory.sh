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
#   Category breakdown — RSS/PSS split by mapping backing:
#     elf_disk  = on-disk .so/.elf/exe (shared libs + main binary)
#     elf_memfd = ELF mapped from memfd (antirev-decrypted libs)
#     heap / stack / anon / vdso / sysv_shm / posix_shm / other
#   Top ELF files by PSS (loaded shared libraries, sorted)
#   SysV shm / POSIX shm / memfd — shared-memory segments visible in /proc/<PID>/maps

set -euo pipefail

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
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

# Parse /proc/<pid>/smaps and bucket Rss/Pss by backing-file category.
# Emits two tab-separated sections on stdout:
#   C<TAB>category<TAB>rss_kb<TAB>pss_kb
#   F<TAB>rss_kb<TAB>pss_kb<TAB>category<TAB>path       (one line per ELF mapping file)
classify_smaps() {
    local pid=$1
    local smaps="/proc/$pid/smaps"
    [[ -r "$smaps" ]] || return 1
    awk '
        function classify(p, perm,    base) {
            if (p == "")                       return "anon"
            if (p ~ /^\[heap\]/)               return "heap"
            if (p ~ /^\[stack/)                return "stack"
            if (p ~ /^\[vvar\]|^\[vdso\]|^\[vsyscall\]/) return "vdso"
            if (p ~ /^\[anon/)                 return "anon"
            if (p ~ /SYSV[0-9a-fA-F]+/)        return "sysv_shm"
            if (p ~ /^\/dev\/shm\//)           return "posix_shm"
            if (p ~ /\/memfd:|^memfd:/)        return "elf_memfd"
            if (p ~ /\.so($|\.)/)              return "elf_disk"
            if (p ~ /\.elf($|[ .])/)           return "elf_disk"
            # executable permission on a real file path => main exe or plugin
            if (index(perm, "x") > 0 && p ~ /^\//) return "elf_disk"
            return "other"
        }
        /^[0-9a-f]+-[0-9a-f]+ / {
            path = ""
            for (i=6; i<=NF; i++) path = path (i==6 ? "" : " ") $i
            cur_cat = classify(path, $2)
            cur_path = path
            next
        }
        /^Rss:/  { cat_rss[cur_cat] += $2
                   if (cur_cat == "elf_disk" || cur_cat == "elf_memfd") {
                       file_rss[cur_path] += $2
                       file_cat[cur_path] = cur_cat
                   } }
        /^Pss:/  { cat_pss[cur_cat] += $2
                   if (cur_cat == "elf_disk" || cur_cat == "elf_memfd") {
                       file_pss[cur_path] += $2
                   } }
        END {
            split("elf_disk elf_memfd heap stack anon sysv_shm posix_shm vdso other", order, " ")
            for (i=1; i<=9; i++) {
                k = order[i]
                if ((k in cat_rss) || (k in cat_pss))
                    printf "C\t%s\t%d\t%d\n", k, cat_rss[k]+0, cat_pss[k]+0
            }
            for (f in file_rss)
                printf "F\t%d\t%d\t%s\t%s\n", file_rss[f], file_pss[f]+0, file_cat[f], f
        }
    ' "$smaps"
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
    printf '%-10s %12s   %s\n' "Field" "Value" "含义"
    printf '%-10s %12s   %s\n' "VmSize" "$(human "${vmsize:-0}")" "虚拟地址空间（当前）"
    printf '%-10s %12s   %s\n' "VmPeak" "$(human "${vmpeak:-0}")" "虚拟地址空间（历史峰值）"
    printf '%-10s %12s   %s\n' "VmRSS"  "$(human "${vmrss:-0}")"  "常驻物理内存（当前）"
    printf '%-10s %12s   %s\n' "VmHWM"  "$(human "${vmhwm:-0}")"  "常驻物理内存（历史峰值）"
    printf '%-10s %12s   %s\n' "VmData" "$(human "${vmdata:-0}")" "堆 + 匿名映射（程序自己申请的部分）"
    printf '%-10s %12s   %s\n' "VmSwap" "$(human "${vmswap:-0}")" "已换出到 swap"
    [[ -n "$pss" ]] && printf '%-10s %12s   %s\n' "Pss" "$(human "$pss")" "按引用数分摊后的共享内存"
    [[ -n "${uss:-}" ]] && printf '%-10s %12s   %s\n' "Uss" "$(human "$uss")" "进程独占（退出即可释放）"

    # category breakdown + per-ELF list (from smaps)
    local smaps_out
    smaps_out=$(classify_smaps "$pid" 2>/dev/null || true)
    if [[ -n "$smaps_out" ]]; then
        echo
        echo "按映射类别统计 (RSS / PSS):"
        printf '%-12s  %12s  %12s\n' "类别" "rss" "pss"
        echo "$smaps_out" | awk -F'\t' '$1=="C"{print $2"\t"$3"\t"$4}' \
            | while IFS=$'\t' read -r cat rss pss; do
                printf '  %-10s  %12s  %12s\n' "$cat" "$(human "$rss")" "$(human "$pss")"
            done

        local elf_lines
        elf_lines=$(echo "$smaps_out" | awk -F'\t' '$1=="F"{print $0}' | sort -t$'\t' -k2,2 -n -r)
        if [[ -n "$elf_lines" ]]; then
            echo
            echo "已加载的 ELF 文件 (按 RSS 排序, 前 20):"
            printf '%12s  %12s  %-10s  %s\n' "rss" "pss" "类型" "路径"
            echo "$elf_lines" | head -20 | while IFS=$'\t' read -r _ rss pss cat path; do
                printf '%12s  %12s  %-10s  %s\n' "$(human "$rss")" "$(human "$pss")" "$cat" "$path"
            done
            local elf_total_rss elf_total_pss
            elf_total_rss=$(echo "$elf_lines" | awk -F'\t' '{s+=$2} END{print s+0}')
            elf_total_pss=$(echo "$elf_lines" | awk -F'\t' '{s+=$3} END{print s+0}')
            printf '%12s  %12s  %-10s  %s\n' \
                "$(human "$elf_total_rss")" "$(human "$elf_total_pss")" "合计" "(所有已加载 ELF)"
        fi
    fi

    # shared-memory segments visible in the process
    local maps="/proc/$pid/maps"
    if [[ -r "$maps" ]]; then
        local shm_lines
        shm_lines=$(grep -E 'SYSV|/dev/shm|/memfd:' "$maps" || true)
        if [[ -n "$shm_lines" ]]; then
            echo
            echo "共享内存 / memfd 映射:"
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
        echo "按 RSS 排序的前 15 个映射 (pmap -x):"
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
