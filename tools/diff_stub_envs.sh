#!/bin/sh
# diff_stub_envs.sh — compare two stub-log dumps from /tmp/antirev_stub.log.
#
# Usage:
#   tools/diff_stub_envs.sh <pid_a> <pid_b> [log_file]
#   tools/diff_stub_envs.sh --by-name <name> [log_file]
#     ^ auto-picks the LAST TWO stub runs whose name matches and diffs them
#   tools/diff_stub_envs.sh --list [log_file]
#     ^ list every stub run in the log with pid + name + ppid
#
# Default log: /tmp/antirev_stub.log
#
# Outputs three diffs side by side: fexecve envp, inherited envp,
# pre-fexecve open fds.  Each is sorted before diffing so set-level
# differences pop out regardless of original order.

set -e

LOG_DEFAULT=/tmp/antirev_stub.log

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

list_runs() {
    log=$1
    [ -r "$log" ] || { echo "log not readable: $log" >&2; exit 1; }
    echo "PID         NAME                          PPID    TIMESTAMP-IF-AVAILABLE"
    grep '===== stub start' "$log" | sed -E \
        's/^\[pid=([0-9]+) name=([^]]+)\] +===== stub start ppid=([0-9]+).*/\1\t\2\t\3/' \
        | column -t
}

extract_section() {
    log=$1
    pid=$2
    section=$3
    # Pull the BEGIN..END block, strip the [pid=N name=X] prefix,
    # drop the BEGIN / END marker lines themselves.
    sed -n "/pid=$pid .*$section BEGIN/,/pid=$pid .*$section END/p" "$log" \
        | sed -E 's/^\[pid=[0-9]+ name=[^]]*\] *//' \
        | grep -v '^---' \
        | grep -v '^$'
}

emit_diff() {
    title=$1
    log=$2
    a=$3
    b=$4
    section=$5

    tmp_a=$(mktemp)
    tmp_b=$(mktemp)
    trap 'rm -f $tmp_a $tmp_b' EXIT

    extract_section "$log" "$a" "$section" | sort -u > "$tmp_a"
    extract_section "$log" "$b" "$section" | sort -u > "$tmp_b"

    a_count=$(wc -l < "$tmp_a")
    b_count=$(wc -l < "$tmp_b")

    echo
    echo "===== $title ====="
    echo "LEFT  pid=$a  ($a_count entries)"
    echo "RIGHT pid=$b  ($b_count entries)"

    if [ ! -s "$tmp_a" ] && [ ! -s "$tmp_b" ]; then
        echo "(both sides empty — section not present in log)"
        return
    fi

    if diff -q "$tmp_a" "$tmp_b" > /dev/null 2>&1; then
        echo "(identical)"
    else
        diff -u --label "pid=$a" --label "pid=$b" "$tmp_a" "$tmp_b" || true
    fi

    rm -f "$tmp_a" "$tmp_b"
}

# ----- arg parsing -----

case "${1-}" in
    --list)
        log=${2:-$LOG_DEFAULT}
        list_runs "$log"
        exit 0
        ;;
    --by-name)
        name=${2-}
        [ -z "$name" ] && usage
        log=${3:-$LOG_DEFAULT}
        [ -r "$log" ] || { echo "log not readable: $log" >&2; exit 1; }
        pids=$(grep '===== stub start' "$log" \
                | grep "name=$name" \
                | sed -E 's/.*pid=([0-9]+).*/\1/' \
                | tail -2)
        n=$(echo "$pids" | wc -w)
        [ "$n" -lt 2 ] && { echo "need at least 2 runs for name='$name', found $n" >&2; exit 1; }
        a=$(echo "$pids" | awk '{print $1}')
        b=$(echo "$pids" | awk '{print $2}')
        ;;
    -h|--help|'')
        usage
        ;;
    *)
        a=$1
        b=${2-}
        [ -z "$b" ] && usage
        log=${3:-$LOG_DEFAULT}
        ;;
esac

[ -r "$log" ] || { echo "log not readable: $log" >&2; exit 1; }

# Verify both pids exist
for p in "$a" "$b"; do
    if ! grep -q "pid=$p " "$log"; then
        echo "pid=$p not found in $log" >&2
        exit 1
    fi
done

emit_diff "fexecve envp"        "$log" "$a" "$b" "fexecve envp"
emit_diff "inherited envp"      "$log" "$a" "$b" "inherited envp"
emit_diff "pre-fexecve open fds" "$log" "$a" "$b" "pre-fexecve open fds"
emit_diff "inherited open fds"  "$log" "$a" "$b" "inherited open fds"
