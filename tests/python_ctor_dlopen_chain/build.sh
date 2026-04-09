#!/bin/bash
# Build the demo libs.
# Run from this directory.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# libzzz.so — leaf (no deps)
gcc -shared -fPIC -Wl,-soname,libzzz.so -o libzzz.so libzzz.c

# libbar.so — links to libzzz.so (DT_NEEDED)
gcc -shared -fPIC -Wl,-soname,libbar.so -o libbar.so libbar.c -L. -lzzz -Wl,-rpath,'$ORIGIN'

# libfoo.so — constructor dlopens libbar.so (no DT_NEEDED on bar)
gcc -shared -fPIC -Wl,-soname,libfoo.so -o libfoo.so libfoo.c -ldl

echo "Built: libfoo.so --(ctor dlopen)--> libbar.so --(DT_NEEDED)--> libzzz.so"
echo ""
echo "Verify linkage:"
echo "  libfoo DT_NEEDED:" && readelf -d libfoo.so | grep NEEDED
echo "  libbar DT_NEEDED:" && readelf -d libbar.so | grep NEEDED
