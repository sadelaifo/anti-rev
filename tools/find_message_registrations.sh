#!/bin/bash
# find_message_registrations — scan all .so / executables under a directory
# and report every file that defines symbols for a given protobuf message
# simple name. Used to detect same-message duplicate registration that
# find_duplicate_proto.sh (which searches by .proto filename) can miss
# when two .proto files share a package.MessageName but live under
# different filenames.
#
# Usage:
#   find_message_registrations.sh <MessageSimpleName> [search-root]
#
# Example:
#   find_message_registrations.sh AMap /path/to/staging
#
# Interpretation:
#   - exactly 1 hit   => no duplication; AMap is defined in one place only.
#                        The "two descriptors" hypothesis is disproved.
#   - 2+ hits         => SMOKING GUN. Multiple .so each compile in their
#                        own copy of the .pb.cc for AMap. Under packed
#                        mode, ctor order can let the "wrong" registration
#                        win the DescriptorPool lookup while the concrete
#                        Message class still uses its own baked-in
#                        descriptor => transcoder/parser schema mismatch
#                        => "json transcoder produced invalid protobuf
#                        output".

set -u

NAME="${1:-}"
ROOT="${2:-.}"

if [ -z "$NAME" ]; then
    echo "usage: $0 <MessageSimpleName> [search-root]" >&2
    echo "  e.g. $0 AMap /path/to/staging" >&2
    exit 1
fi

if [ ! -d "$ROOT" ]; then
    echo "FAIL: search root '$ROOT' is not a directory" >&2
    exit 1
fi

echo "Searching under: $ROOT"
echo "Looking for registrations of message: $NAME"
echo

# Patterns that a generated .pb.cc will define for message Foo:
#   _ZN...Foo10descriptorEv              (static descriptor())
#   _ZN...6FooPOD..._default_instance_  (default instance storage)
#   _ZTVN...FooE                         (vtable)
#   _ZN...Foo.*_InitDefaults
# We match on the simple name appearing inside a mangled C++ symbol that
# also contains one of these give-away fragments.

hits=0
total=0

# Use a tmpfile so we can count in parent shell (find|while runs in subshell).
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

find "$ROOT" -type f \( -name '*.so' -o -name '*.so.*' -o -executable \) 2>/dev/null \
  | while read -r f; do
    echo "." >> "$tmp"      # one char per file scanned (count later)
    readelf -h "$f" >/dev/null 2>&1 || continue

    # Look for defined symbols mentioning the message name together with
    # any telltale generated-code suffix.
    syms=$(nm -D --defined-only "$f" 2>/dev/null \
           | grep -E "${NAME}.*(descriptor|_default_instance_|_InitDefaults|GetDescriptor|GetMetadata|_ZTVN)" \
           | head -8)
    if [ -n "$syms" ]; then
        echo "=== HIT: $f ==="
        echo "$syms"
        echo
        echo "H" >> "$tmp"
    fi
done

total=$(grep -c '\.' "$tmp" 2>/dev/null || echo 0)
hits=$(grep -c 'H' "$tmp" 2>/dev/null || echo 0)

echo "---"
echo "scanned: $total files"
echo "hits:    $hits"
echo
if [ "$hits" -ge 2 ]; then
    echo ">>> SMOKING GUN: ${NAME} is defined in $hits files."
    echo ">>> Two or more .so each compile a copy of the generated code."
    echo ">>> Under packed mode the wrong one can win the DescriptorPool"
    echo ">>> lookup, causing JsonStringToMessage to emit bytes the"
    echo ">>> concrete Message class cannot parse."
elif [ "$hits" = "1" ]; then
    echo "Only one definition found. Duplicate-registration hypothesis is"
    echo "disproved for ${NAME}. Run again with other message names"
    echo "(BMap, CMap, ...) before moving on."
else
    echo "No hits. Check:"
    echo "  - is '$NAME' actually the simple name (no package prefix)?"
    echo "  - is '$ROOT' pointing at the UNENCRYPTED staging tree?"
    echo "  - try with a known-good reference name to verify plumbing"
fi
