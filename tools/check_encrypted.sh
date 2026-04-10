#!/bin/sh
# Check which ELF files (exe/so) are encrypted by anti-rev.
# Usage: ./check_encrypted.sh <directory>
# Example: ./check_encrypted.sh /opt/myapp

DIR="${1:-.}"

if [ ! -d "$DIR" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

total=0
encrypted=0
plain=0

find "$DIR" -type f | while read -r f; do
    # Check if ELF (magic: 7f 45 4c 46)
    header=$(head -c 4 "$f" 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' ')
    [ "$header" = "7f454c46" ] || continue

    total=$((total + 1))
    magic=$(tail -c 8 "$f" 2>/dev/null)
    if [ "$magic" = "ANTREV01" ]; then
        encrypted=$((encrypted + 1))
        echo "[encrypted] $f"
    else
        plain=$((plain + 1))
        echo "[plain]     $f"
    fi
done

echo ""
echo "Total ELF: $total  Encrypted: $encrypted  Plain: $plain"
