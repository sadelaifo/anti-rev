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

for f in $(find "$DIR" -type f 2>/dev/null); do
    # Check ELF: skip \x7f (confuses grep), match "ELF" from bytes 2-4
    dd if="$f" bs=1 skip=1 count=3 2>/dev/null | grep -q "ELF" || continue

    total=$((total + 1))

    # Check anti-rev magic in last 8 bytes (pipe, no variable)
    if tail -c 8 "$f" 2>/dev/null | grep -q "ANTREV01"; then
        encrypted=$((encrypted + 1))
        echo "[encrypted] $f"
    else
        plain=$((plain + 1))
        echo "[plain]     $f"
    fi
done

echo ""
echo "Total ELF: $total  Encrypted: $encrypted  Plain: $plain"
