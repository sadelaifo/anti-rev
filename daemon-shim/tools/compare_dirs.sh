#!/bin/bash
# compare_dirs.sh — compare original and protected directories
#
# Usage: compare_dirs.sh <original_dir> <protected_dir>
#
# Lists which files are protected (encrypted exe or encrypted lib)
# and which are unprotected (identical to original).

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <original_dir> <protected_dir>" >&2
    exit 1
fi

ORIG="$1"
PROT="$2"

if [ ! -d "$ORIG" ]; then echo "Error: $ORIG not found" >&2; exit 1; fi
if [ ! -d "$PROT" ]; then echo "Error: $PROT not found" >&2; exit 1; fi

MAGIC_HEX="414e545245563031"  # "ANTREV01"

protected=0
unprotected=0
missing=0

echo "=== Comparing: $ORIG vs $PROT ==="
echo ""

printf "%-60s %s\n" "FILE" "STATUS"
printf "%-60s %s\n" "----" "------"

while IFS= read -r -d '' file; do
    rel="${file#$ORIG/}"
    prot_file="$PROT/$rel"

    if [ ! -f "$prot_file" ]; then
        printf "%-60s %s\n" "$rel" "MISSING"
        missing=$((missing + 1))
        continue
    fi

    # Check if protected file contains ANTREV01 magic
    # For encrypted libs: magic is at offset 0
    # For protected exes: magic is in the last 8 bytes of the trailer
    is_protected=0

    # Check last 8 bytes (exe trailer magic)
    tail_hex=$(tail -c 8 "$prot_file" 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
    if [ "$tail_hex" = "$MAGIC_HEX" ]; then
        is_protected=1
    fi

    # Check first 8 bytes (encrypted lib magic)
    if [ "$is_protected" -eq 0 ]; then
        head_hex=$(head -c 8 "$prot_file" 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
        if [ "$head_hex" = "$MAGIC_HEX" ]; then
            is_protected=1
        fi
    fi

    if [ "$is_protected" -eq 1 ]; then
        printf "%-60s %s\n" "$rel" "PROTECTED"
        protected=$((protected + 1))
    else
        printf "%-60s %s\n" "$rel" "unprotected"
        unprotected=$((unprotected + 1))
    fi
done < <(find "$ORIG" -type f -print0 | sort -z)

echo ""
echo "=== Summary ==="
echo "Protected:   $protected"
echo "Unprotected: $unprotected"
echo "Missing:     $missing"
echo "Total:       $((protected + unprotected + missing))"
