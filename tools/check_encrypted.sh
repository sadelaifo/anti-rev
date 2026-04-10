#!/bin/sh
# Check which ELF files (exe/so) are encrypted by anti-rev.
# Usage: ./check_encrypted.sh <directory>

DIR="${1:-.}"

if [ ! -d "$DIR" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

total=0
encrypted=0
plain=0

find "$DIR" -type f -print0 2>/dev/null | xargs -0 file 2>/dev/null | grep "ELF" | cut -d: -f1 | while IFS= read -r f; do
    total=$((total + 1))
    magic=$(tail -c 8 "$f" 2>/dev/null)
    if [ "$magic" = "ANTREV01" ]; then
        encrypted=$((encrypted + 1))
        echo "[encrypted] $f"
    else
        plain=$((plain + 1))
        echo "[plain]     $f"
    fi
    # Write counters to temp file (subshell workaround)
    echo "$total $encrypted $plain" > /tmp/.antirev_check_count
done

if [ -f /tmp/.antirev_check_count ]; then
    read total encrypted plain < /tmp/.antirev_check_count
    rm -f /tmp/.antirev_check_count
fi

echo ""
echo "Total ELF: $total  Encrypted: $encrypted  Plain: $plain"
