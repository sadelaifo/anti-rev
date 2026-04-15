#!/bin/bash
# Build json_trace.so on the aarch64 target.
# Must be built on the SAME system whose libprotobuf you want to
# intercept — the header/ABI has to match.
set -e
cd "$(dirname "$0")"
g++ -O2 -fPIC -shared -std=c++17 \
    -o json_trace.so json_trace.cc \
    -ldl -lprotobuf
echo "built: $(pwd)/json_trace.so"
echo
echo "usage:"
echo "  LD_PRELOAD=$(pwd)/json_trace.so:\$LD_PRELOAD <your broken cmd>"
