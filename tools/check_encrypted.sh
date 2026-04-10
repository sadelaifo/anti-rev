#!/bin/sh
# Check which ELF files (exe/so) are encrypted by anti-rev.
# Usage: ./check_encrypted.sh <directory>

DIR="${1:-.}"

if [ ! -d "$DIR" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

ELF_MAGIC=$(printf '\177ELF')
total=0
encrypted=0
plain=0

for f in $(find "$DIR" -type f 2>/dev/null); do
    # ELF detection: compare first 4 bytes with \x7fELF via dd+printf
    header=$(dd if="$f" bs=1 count=4 2>/dev/null)
    [ "$header" = "$ELF_MAGIC" ] || continue

    total=$((total + 1))

    # ANTREV01 check: pipe to grep (pure ASCII, no null byte issues)
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
