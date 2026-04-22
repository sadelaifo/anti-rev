#!/bin/sh
# Check which ELF / .so / .elf files are encrypted by anti-rev.
# Usage: ./check_encrypted.sh <directory>
#
# Recognizes two encrypted formats:
#   - Protected exe: stub ELF + bundle + trailer ending in "ANTREV01".
#     Header is still \x7fELF (the stub); we detect via tail magic.
#   - Encrypted lib/.elf asset: "ANTREV01" + iv + tag + ciphertext.
#     Header is NOT \x7fELF (first 8 bytes are the magic).

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
    is_elf_header=0
    is_libasset=0

    # Name-based lib-asset detection: .so / .so.N / .elf
    case "$name" in
        *.so|*.so.*|*.elf) is_libasset=1 ;;
    esac

    # Magic-based ELF-header detection
    { header=$(dd if="$f" bs=1 count=4 2>/dev/null); } 2>/dev/null
    [ "$header" = "$ELF_MAGIC" ] && is_elf_header=1

    # Only report ELF-header files and lib-asset-named files
    [ $is_elf_header -eq 0 ] && [ $is_libasset -eq 0 ] && continue

    total=$((total + 1))

    if [ $is_elf_header -eq 1 ]; then
        # Header is \x7fELF — either a plaintext ELF or a protected
        # exe whose trailer ends in ANTREV01.
        if tail -c 8 "$f" 2>/dev/null | grep -q "ANTREV01"; then
            encrypted=$((encrypted + 1))
            echo "[encrypted] $f"
        else
            plain=$((plain + 1))
            echo "[plain]     $f"
        fi
    else
        # Name is .so/.elf but header is not \x7fELF — treat as
        # antirev-encrypted lib asset (ANTREV01 magic prefix).
        encrypted=$((encrypted + 1))
        echo "[encrypted] $f"
    fi
done

echo ""
echo "Total: $total  Encrypted: $encrypted  Plain: $plain"
