#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/project"
ENCRYPTOR="$SCRIPT_DIR/../encryptor/protect.py"
STUB="$SCRIPT_DIR/../build/stub"

cd "$PROJECT_DIR"

echo "============================================================"
echo "  antirev Benchmark — $(date)"
echo "============================================================"
echo ""

# ----------------------------------------------------------------
# 1. Build
# ----------------------------------------------------------------
echo ">>> [1/6] Building project..."
BUILD_START=$(date +%s%N)
make -j"$(nproc)" 2>&1
BUILD_END=$(date +%s%N)
BUILD_TIME_MS=$(( (BUILD_END - BUILD_START) / 1000000 ))
echo "    Build time: ${BUILD_TIME_MS} ms"
echo ""

# ----------------------------------------------------------------
# 2. Record original sizes
# ----------------------------------------------------------------
MAIN_ORIG_SIZE=$(stat -c%s main_bin)
WORKER_ORIG_SIZE=$(stat -c%s worker_bin)
echo ">>> [2/6] Original sizes:"
echo "    main_bin:   ${MAIN_ORIG_SIZE} bytes"
echo "    worker_bin: ${WORKER_ORIG_SIZE} bytes"
echo ""

# ----------------------------------------------------------------
# 3. Protect main_bin and worker_bin, record time
# ----------------------------------------------------------------
echo ">>> [3/6] Protecting binaries..."

PROTECT_MAIN_START=$(date +%s%N)
python3 "$ENCRYPTOR" \
    --stub "$STUB" \
    --main main_bin \
    --key  bench_main.key \
    --output main_bin.protected
PROTECT_MAIN_END=$(date +%s%N)
PROTECT_MAIN_MS=$(( (PROTECT_MAIN_END - PROTECT_MAIN_START) / 1000000 ))

PROTECT_WORKER_START=$(date +%s%N)
python3 "$ENCRYPTOR" \
    --stub "$STUB" \
    --main worker_bin \
    --key  bench_worker.key \
    --output worker_bin.protected
PROTECT_WORKER_END=$(date +%s%N)
PROTECT_WORKER_MS=$(( (PROTECT_WORKER_END - PROTECT_WORKER_START) / 1000000 ))

MAIN_PROT_SIZE=$(stat -c%s main_bin.protected)
WORKER_PROT_SIZE=$(stat -c%s worker_bin.protected)

echo "    protect main_bin:   ${PROTECT_MAIN_MS} ms"
echo "    protect worker_bin: ${PROTECT_WORKER_MS} ms"
echo "    main_bin.protected:   ${MAIN_PROT_SIZE} bytes"
echo "    worker_bin.protected: ${WORKER_PROT_SIZE} bytes"
echo ""

# ----------------------------------------------------------------
# 4. Build and protect noop binary
# ----------------------------------------------------------------
echo ">>> [4/6] Building noop binary..."
cat > /tmp/antirev_noop.c << 'EOF'
int main(void) { return 0; }
EOF
gcc -O2 -o /tmp/antirev_noop /tmp/antirev_noop.c

NOOP_ORIG_SIZE=$(stat -c%s /tmp/antirev_noop)

python3 "$ENCRYPTOR" \
    --stub "$STUB" \
    --main /tmp/antirev_noop \
    --key  /tmp/antirev_noop.key \
    --output /tmp/antirev_noop.protected

NOOP_PROT_SIZE=$(stat -c%s /tmp/antirev_noop.protected)
echo "    noop orig size:      ${NOOP_ORIG_SIZE} bytes"
echo "    noop protected size: ${NOOP_PROT_SIZE} bytes"
echo ""

# ----------------------------------------------------------------
# Helper: median of 5 timing runs (in milliseconds)
# ----------------------------------------------------------------
measure_time_ms() {
    local binary="$1"
    local times=()
    for run in 1 2 3 4 5; do
        local t_start t_end elapsed_ms
        t_start=$(date +%s%N)
        "$binary" > /dev/null 2>&1 || true
        t_end=$(date +%s%N)
        elapsed_ms=$(( (t_end - t_start) / 1000000 ))
        times+=("$elapsed_ms")
    done
    # Sort and take median (index 2 of 0-based sorted array)
    IFS=$'\n' sorted=($(sort -n <<< "${times[*]}")); unset IFS
    echo "${sorted[2]}"
}

# ----------------------------------------------------------------
# 5. Execution time measurements
# ----------------------------------------------------------------
echo ">>> [5/6] Measuring execution times (5 runs each, median)..."

echo "    Timing noop (original)..."
NOOP_ORIG_MS=$(measure_time_ms /tmp/antirev_noop)

echo "    Timing noop (protected)..."
NOOP_PROT_MS=$(measure_time_ms /tmp/antirev_noop.protected)

echo "    Timing main_bin (original)..."
MAIN_ORIG_MS=$(measure_time_ms ./main_bin)

echo "    Timing main_bin (protected)..."
MAIN_PROT_MS=$(measure_time_ms ./main_bin.protected)

echo ""

# ----------------------------------------------------------------
# 6. Peak RSS measurements
# ----------------------------------------------------------------
echo ">>> [6/6] Measuring peak RSS..."

get_rss_kb() {
    local binary="$1"
    /usr/bin/time -v "$binary" > /dev/null 2>/tmp/antirev_time_out || true
    grep "Maximum resident" /tmp/antirev_time_out | awk '{print $NF}'
}

NOOP_ORIG_RSS=$(get_rss_kb /tmp/antirev_noop)
NOOP_PROT_RSS=$(get_rss_kb /tmp/antirev_noop.protected)
MAIN_ORIG_RSS=$(get_rss_kb ./main_bin)
MAIN_PROT_RSS=$(get_rss_kb ./main_bin.protected)

echo "    noop orig RSS:      ${NOOP_ORIG_RSS} KB"
echo "    noop prot RSS:      ${NOOP_PROT_RSS} KB"
echo "    main_bin orig RSS:  ${MAIN_ORIG_RSS} KB"
echo "    main_bin prot RSS:  ${MAIN_PROT_RSS} KB"
echo ""

# ----------------------------------------------------------------
# Compute derived metrics
# ----------------------------------------------------------------
DECRYPTION_SLOWDOWN_MS=$(( NOOP_PROT_MS - NOOP_ORIG_MS ))
RUNTIME_OVERHEAD_MS=$(( MAIN_PROT_MS - MAIN_ORIG_MS - DECRYPTION_SLOWDOWN_MS ))

MAIN_SIZE_OVERHEAD_BYTES=$(( MAIN_PROT_SIZE - MAIN_ORIG_SIZE ))
MAIN_SIZE_OVERHEAD_PCT=$(python3 -c "print(f'{($MAIN_PROT_SIZE - $MAIN_ORIG_SIZE) / $MAIN_ORIG_SIZE * 100:.1f}')")

WORKER_SIZE_OVERHEAD_BYTES=$(( WORKER_PROT_SIZE - WORKER_ORIG_SIZE ))
WORKER_SIZE_OVERHEAD_PCT=$(python3 -c "print(f'{($WORKER_PROT_SIZE - $WORKER_ORIG_SIZE) / $WORKER_ORIG_SIZE * 100:.1f}')")

INIT_MEM_OVERHEAD_KB=$(( NOOP_PROT_RSS - NOOP_ORIG_RSS ))
MAIN_MEM_OVERHEAD_KB=$(( MAIN_PROT_RSS - MAIN_ORIG_RSS ))

# ----------------------------------------------------------------
# Print results table
# ----------------------------------------------------------------
echo "============================================================"
echo "  RESULTS SUMMARY"
echo "============================================================"
printf "%-40s %s\n" "Metric" "Value"
echo "------------------------------------------------------------"
printf "%-40s %s ms\n"  "1. Protection time (main_bin)"   "$PROTECT_MAIN_MS"
printf "%-40s %s ms\n"  "   Protection time (worker_bin)" "$PROTECT_WORKER_MS"
echo ""
printf "%-40s %s bytes (+%s%%)\n" "2. Disk size overhead (main_bin)" \
    "$MAIN_SIZE_OVERHEAD_BYTES" "$MAIN_SIZE_OVERHEAD_PCT"
printf "%-40s %s bytes (+%s%%)\n" "   Disk size overhead (worker_bin)" \
    "$WORKER_SIZE_OVERHEAD_BYTES" "$WORKER_SIZE_OVERHEAD_PCT"
printf "%-40s %s bytes (orig)  →  %s bytes (prot)\n" \
    "   main_bin sizes:" "$MAIN_ORIG_SIZE" "$MAIN_PROT_SIZE"
printf "%-40s %s bytes (orig)  →  %s bytes (prot)\n" \
    "   worker_bin sizes:" "$WORKER_ORIG_SIZE" "$WORKER_PROT_SIZE"
echo ""
printf "%-40s %s\n" "3. In-memory size overhead (AES-GCM)" \
    "0 bytes (ciphertext == plaintext length)"
echo ""
printf "%-40s %s KB (orig)  →  %s KB (prot)  [delta: %s KB]\n" \
    "4. Init memory overhead (noop RSS):" \
    "$NOOP_ORIG_RSS" "$NOOP_PROT_RSS" "$INIT_MEM_OVERHEAD_KB"
printf "%-40s %s KB (orig)  →  %s KB (prot)  [delta: %s KB]\n" \
    "   Runtime memory overhead (main):" \
    "$MAIN_ORIG_RSS" "$MAIN_PROT_RSS" "$MAIN_MEM_OVERHEAD_KB"
echo ""
printf "%-40s %s ms (orig)  →  %s ms (prot)  [delta: %s ms]\n" \
    "5. Decryption slowdown (noop):" \
    "$NOOP_ORIG_MS" "$NOOP_PROT_MS" "$DECRYPTION_SLOWDOWN_MS"
echo ""
printf "%-40s %s ms (orig)  →  %s ms (prot)\n" \
    "6. Runtime overhead (main_bin):" \
    "$MAIN_ORIG_MS" "$MAIN_PROT_MS"
printf "%-40s %s ms  (after subtracting decryption)\n" \
    "   Net runtime overhead:" "$RUNTIME_OVERHEAD_MS"
echo "============================================================"
echo ""
echo "Raw data:"
printf "  Build time:              %s ms\n"   "$BUILD_TIME_MS"
printf "  protect main_bin time:   %s ms\n"   "$PROTECT_MAIN_MS"
printf "  protect worker_bin time: %s ms\n"   "$PROTECT_WORKER_MS"
printf "  noop orig: %s ms  |  noop prot: %s ms\n"   "$NOOP_ORIG_MS" "$NOOP_PROT_MS"
printf "  main orig: %s ms  |  main prot: %s ms\n"   "$MAIN_ORIG_MS" "$MAIN_PROT_MS"
printf "  noop orig RSS: %s KB  |  noop prot RSS: %s KB\n" "$NOOP_ORIG_RSS" "$NOOP_PROT_RSS"
printf "  main orig RSS: %s KB  |  main prot RSS: %s KB\n" "$MAIN_ORIG_RSS" "$MAIN_PROT_RSS"
echo "============================================================"
