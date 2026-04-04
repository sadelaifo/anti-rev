#!/bin/bash
# Build the demo libs.
# Run from this directory.
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# libtee.so — encrypted leaf (no deps)
gcc -shared -fPIC -Wl,-soname,libtee.so -o libtee.so libtee.c

# libbar.so — unencrypted intermediary, links to libtee.so
gcc -shared -fPIC -Wl,-soname,libbar.so -o libbar.so libbar.c -L. -ltee -Wl,-rpath,'$ORIGIN'

# libfoo.so — encrypted top-level, links to libbar.so
gcc -shared -fPIC -Wl,-soname,libfoo.so -o libfoo.so libfoo.c -L. -lbar -Wl,-rpath,'$ORIGIN'

echo "Built: libfoo.so -> libbar.so -> libtee.so"
echo ""
echo "Verify linkage:"
echo "  libfoo DT_NEEDED:" && readelf -d libfoo.so | grep NEEDED
echo "  libbar DT_NEEDED:" && readelf -d libbar.so | grep NEEDED
echo ""
echo "Next steps:"
echo "  1. Pack with antirev-pack.py (encrypt libfoo.so + libtee.so, skip libbar.so)"
echo "  2. Start .antirev-libd"
echo "  3. Run: python3 demo.py /path/to/.antirev-libd"
