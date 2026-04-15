#!/bin/bash
# find_duplicate_proto — locate .so / executables that register the same
# protobuf message type, which is the prime suspect for
# "json transcoder produced invalid protobuf output" after antirev packing.
#
# Background:
#   protobuf's JsonStringToMessage internally writes binary bytes using a
#   descriptor looked up by full_name in generated_pool, then ParseFromString's
#   them back. If TWO .so files each statically link the same .pb.cc, both
#   register into generated_pool. Packing can change ctor order so the "wrong"
#   one wins the lookup while the concrete Message class still carries its
#   own baked-in descriptor — wire layout mismatches → that error.
#
# Usage:
#   find_duplicate_proto.sh <message.full.name> [search-root]
#
# Example:
#   find_duplicate_proto.sh myapp.RequestConfig /opt/business
#
# If you don't know the full name, add one log line in the failing code:
#   std::cerr << msg->GetDescriptor()->full_name() << "\n";
# and rerun the broken component once.

set -u

TYPE="${1:-}"
ROOT="${2:-.}"

if [ -z "$TYPE" ]; then
    echo "usage: $0 <message.full.name> [search-root]" >&2
    echo "  e.g. $0 myapp.RequestConfig /opt/business" >&2
    exit 1
fi

# protobuf's generated AddDescriptors function name mangles '.' and '/' to '_'
# and uses the .proto FILE name, not the message name. So we match on the
# full_name string appearing in the .so rodata as a first pass, then report
# any protobuf-registration symbols that look related.
TYPE_UNDERSCORE=$(echo "$TYPE" | tr './' '__')

echo "Searching under: $ROOT"
echo "Looking for type: $TYPE"
echo

hits=0
find "$ROOT" -type f \( -name '*.so' -o -name '*.so.*' -o -executable \) 2>/dev/null \
  | while read -r f; do
    # Skip non-ELF quickly
    head -c 4 "$f" 2>/dev/null | grep -q $'\x7fELF' || continue

    if strings -a "$f" 2>/dev/null | grep -qF "$TYPE"; then
        # Does this file also contain a protobuf descriptor-registration
        # symbol? Look for any AddDescriptors_* or descriptor_table_* symbol.
        reg=$(nm -D --defined-only "$f" 2>/dev/null \
              | grep -cE '(AddDescriptors_|descriptor_table_|InitDefaults_)' \
              || true)
        printf '  HIT  %-70s  pbreg_syms=%s\n' "$f" "$reg"
        hits=$((hits+1))
    fi
done

echo
cat <<'EOF'
Interpretation:
  - 0 or 1 hits      => not a duplicate-proto problem; look elsewhere
                        (check ctor ordering of the failing module, or add
                         diagnostic prints around the JsonStringToMessage call)
  - 2+ hits with
    pbreg_syms > 0   => SMOKING GUN. Two+ files register descriptors for
                        this type. Under packed/daemon mode the ctor order
                        can make the "wrong" one win the lookup.
                        Fix: make exactly one .so own the .pb.cc for this
                        type; have the other dlopen it or link against it
                        dynamically instead of bundling its own copy.
  - 2+ hits but
    pbreg_syms = 0   => string may be mentioned in config/hardcoded JSON
                        rather than registered. Double-check with:
                          nm -D <file> | grep -i <type-underscored>
EOF
