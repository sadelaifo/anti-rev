#!/bin/sh
# Check which ELF/SO files are encrypted by anti-rev.
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
    name=$(basename "$f")
    is_elf=0
    is_so=0

    # Check if .so file
    case "$name" in
        *.so|*.so.*) is_so=1 ;;
    esac

    # Check ELF magic
    { header=$(dd if="$f" bs=1 count=4 2>/dev/null); } 2>/dev/null
    [ "$header" = "$ELF_MAGIC" ] && is_elf=1

    # Only check ELF files and .so files
    [ $is_elf -eq 0 ] && [ $is_so -eq 0 ] && continue

    total=$((total + 1))

    # Encrypted exe: ELF + ANTREV01 trailer
    # Encrypted lib: .so but no longer ELF (content is ciphertext)
    if [ $is_elf -eq 1 ]; then
        if tail -c 8 "$f" 2>/dev/null | grep -q "ANTREV01"; then
            encrypted=$((encrypted + 1))
            echo "[encrypted] $f"
        else
            plain=$((plain + 1))
            echo "[plain]     $f"
        fi
    else
        # .so file that's not ELF = encrypted by anti-rev
        encrypted=$((encrypted + 1))
        echo "[encrypted] $f"
    fi
done

echo ""
echo "Total: $total  Encrypted: $encrypted  Plain: $plain"
