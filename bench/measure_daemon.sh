#!/usr/bin/env bash
#
# Daemon-mode benchmark: 500 libs + 130 exes, ~5MB each.
#
# Measures:
#   1. antirev-libd startup overhead  (decrypt 500 * 5MB libs)
#   2. exe startup overhead           (connect daemon, receive fds, fexecve)
#   3. exe lib link overhead          (LD_PRELOAD lib loading by dynamic linker)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT="$SCRIPT_DIR/daemon_project"
PROTECT="$ROOT_DIR/encryptor/protect.py"
STUB="$ROOT_DIR/build/stub"

LIBS_DIR="$PROJECT/libs"
EXES_DIR="$PROJECT/exes"
OUT_DIR="$PROJECT/protected"
KEY_FILE="$PROJECT/bench.key"

N_RUNS=3  # runs per exe measurement, take median
N_DAEMON_RUNS=1  # daemon runs (each decrypts 2.5GB, takes minutes)

# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

now_ns() { date +%s%N; }

elapsed_ms() {
    local start=$1 end=$2
    echo $(( (end - start) / 1000000 ))
}

median() {
    local -a sorted
    IFS=$'\n' sorted=($(sort -n <<< "$*")); unset IFS
    local mid=$(( ${#sorted[@]} / 2 ))
    echo "${sorted[$mid]}"
}

kill_daemons() {
    pkill -x '.antirev-libd' 2>/dev/null || true
    sleep 0.3
}

echo "============================================================"
echo "  antirev Daemon Benchmark — $(date)"
echo "============================================================"
echo ""

# ──────────────────────────────────────────────────────────────────
# 0. Generate project if needed
# ──────────────────────────────────────────────────────────────────
if [ ! -d "$LIBS_DIR" ] || [ "$(ls "$LIBS_DIR"/*.so 2>/dev/null | wc -l)" -lt 500 ]; then
    echo ">>> [0] Generating benchmark project..."
    python3 "$SCRIPT_DIR/gen_daemon_bench.py"
    echo ""
fi

N_LIBS=$(ls "$LIBS_DIR"/*.so 2>/dev/null | wc -l)
N_EXES=$(ls "$EXES_DIR"/exe_* 2>/dev/null | wc -l)
TOTAL_LIB_SIZE=$(du -sb "$LIBS_DIR" | cut -f1)
TOTAL_EXE_SIZE=$(du -sb "$EXES_DIR" | cut -f1)
TOTAL_SIZE=$(( TOTAL_LIB_SIZE + TOTAL_EXE_SIZE ))

echo ">>> Project: ${N_LIBS} libs + ${N_EXES} exes"
echo "    Libs total:  $(( TOTAL_LIB_SIZE / 1048576 )) MB"
echo "    Exes total:  $(( TOTAL_EXE_SIZE / 1048576 )) MB"
echo "    Grand total: $(( TOTAL_SIZE / 1048576 )) MB"
echo ""

# ──────────────────────────────────────────────────────────────────
# 1. Pre-encryption baselines (need unencrypted libs on disk)
# ──────────────────────────────────────────────────────────────────
echo ">>> [1/6] Building linked exe and measuring baselines..."

# Check if libs are still unencrypted (re-run after encryption needs regen)
if ! readelf -h "$LIBS_DIR/lib_0001.so" &>/dev/null; then
    echo "    Libs already encrypted — regenerating..."
    python3 "$SCRIPT_DIR/gen_daemon_bench.py"
fi

# Build an exe that DT_NEEDs all 500 libs
LINKED_SRC="$PROJECT/src/linked_exe.c"
mkdir -p "$(dirname "$LINKED_SRC")"
{
    for i in $(seq 1 $N_LIBS); do
        printf 'extern int lib_%04d_func(int);\n' "$i"
    done
    echo 'int main(void) {'
    echo '    volatile int sum = 0;'
    for i in $(seq 1 $N_LIBS); do
        printf '    sum += lib_%04d_func(0);\n' "$i"
    done
    echo '    return 0;'
    echo '}'
} > "$LINKED_SRC"

LINK_FLAGS=""
for i in $(seq 1 $N_LIBS); do
    LINK_FLAGS="$LINK_FLAGS -l_$(printf '%04d' "$i")"
done

gcc -O2 -o "$EXES_DIR/exe_linked" "$LINKED_SRC" \
    -L"$LIBS_DIR" $LINK_FLAGS -Wl,-rpath,'$ORIGIN/../libs'

# 1a. Unprotected noop exe baseline
echo "    [1a] Unprotected noop exe..."
orig_times=()
for run in $(seq 1 $N_RUNS); do
    T_START=$(now_ns)
    "$EXES_DIR/exe_0001" 2>/dev/null
    T_END=$(now_ns)
    orig_times+=("$(elapsed_ms "$T_START" "$T_END")")
done
EXE_ORIG_MS=$(median "${orig_times[@]}")
echo "    Noop exe median: ${EXE_ORIG_MS} ms"

# 1b. Unprotected linked exe baseline
echo "    [1b] Unprotected linked exe (DT_NEEDED ${N_LIBS} libs)..."
linked_orig_times=()
for run in $(seq 1 $N_RUNS); do
    T_START=$(now_ns)
    LD_LIBRARY_PATH="$LIBS_DIR" "$EXES_DIR/exe_linked" 2>/dev/null
    T_END=$(now_ns)
    linked_orig_times+=("$(elapsed_ms "$T_START" "$T_END")")
done
LINKED_ORIG_MS=$(median "${linked_orig_times[@]}")
echo "    Linked exe median: ${LINKED_ORIG_MS} ms"

# 1c. RSS baselines
echo "    [1c] RSS measurements..."
get_rss_kb() {
    /usr/bin/time -v "$@" > /dev/null 2>/tmp/antirev_bench_time || true
    grep "Maximum resident" /tmp/antirev_bench_time | awk '{print $NF}'
}
EXE_ORIG_RSS=$(get_rss_kb "$EXES_DIR/exe_0001")
LINKED_ORIG_RSS=$(LD_LIBRARY_PATH="$LIBS_DIR" get_rss_kb "$EXES_DIR/exe_linked")
echo "    Noop exe RSS:   ${EXE_ORIG_RSS} KB"
echo "    Linked exe RSS: ${LINKED_ORIG_RSS} KB"
echo ""

# ──────────────────────────────────────────────────────────────────
# 2. Encrypt libs in-place + protect exe
# ──────────────────────────────────────────────────────────────────
echo ">>> [2/6] Encrypting ${N_LIBS} libs in-place (parallel)..."

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

if [ ! -f "$KEY_FILE" ]; then
    python3 -c "import os; open('$KEY_FILE','w').write(os.urandom(32).hex()+'\n')"
fi

# Check if libs already encrypted (ANTREV01 magic = 0x41 0x4e 0x54 0x52 0x45 0x56 0x30 0x31)
FIRST_8=$(xxd -l 8 -p "$LIBS_DIR/lib_0001.so" 2>/dev/null || echo "")
if [ "$FIRST_8" = "414e545245563031" ]; then
    echo "    Libs already encrypted, skipping..."
    ENC_LIBS_MS="(cached)"
else
    T_ENC_START=$(now_ns)
    python3 -c "
import os, sys
from pathlib import Path
sys.path.insert(0, '$ROOT_DIR/encryptor')
from protect import load_or_create_key, encrypt_data, MAGIC
from concurrent.futures import ProcessPoolExecutor, as_completed

key = load_or_create_key(Path('$KEY_FILE'))
lib_dir = '$LIBS_DIR'
libs = sorted(f for f in os.listdir(lib_dir) if f.endswith('.so'))

def enc_one(name):
    path = os.path.join(lib_dir, name)
    data = open(path, 'rb').read()
    iv, tag, ct = encrypt_data(data, key)
    open(path, 'wb').write(MAGIC + iv + tag + ct)
    return name

with ProcessPoolExecutor(max_workers=os.cpu_count()) as pool:
    futs = {pool.submit(enc_one, n): n for n in libs}
    done = 0
    for f in as_completed(futs):
        f.result()
        done += 1
        if done % 100 == 0 or done == len(libs):
            print(f'  encrypted {done}/{len(libs)} libs')
print(f'  Encrypted {len(libs)} libs in-place')
"
    T_ENC_END=$(now_ns)
    ENC_LIBS_MS=$(elapsed_ms "$T_ENC_START" "$T_ENC_END")
    echo "    Lib encryption: ${ENC_LIBS_MS} ms"
fi

# Build lightweight daemon IN the libs dir (it scans its own dir for .so files)
python3 -c "
import struct, os
stub = open('$STUB', 'rb').read()
key  = bytes.fromhex(open('$KEY_FILE').read().strip())
bundle = struct.pack('<IB', 0, 0)
offset = len(stub)
trailer = struct.pack('<Q', offset) + key + b'ANTREV01'
out = '$LIBS_DIR/.antirev-libd'
open(out, 'wb').write(stub + bundle + trailer)
os.chmod(out, 0o755)
"

# Protect the noop exe and the linked exe
python3 "$PROTECT" protect-exe \
    --stub "$STUB" --main "$EXES_DIR/exe_0001" \
    --key "$KEY_FILE" --daemon-libs \
    --output "$OUT_DIR/exe_0001.protected" 2>/dev/null

python3 "$PROTECT" protect-exe \
    --stub "$STUB" --main "$EXES_DIR/exe_linked" \
    --key "$KEY_FILE" --daemon-libs \
    --output "$OUT_DIR/exe_linked.protected" 2>/dev/null

echo ""

# ──────────────────────────────────────────────────────────────────
# 3. Measure daemon startup overhead
# ──────────────────────────────────────────────────────────────────
echo ">>> [3/6] Measuring daemon startup time (${N_DAEMON_RUNS} run(s))..."
echo "    (decrypt ${N_LIBS} * 5MB = ~2.5GB from disk)"

daemon_times=()
for run in $(seq 1 $N_DAEMON_RUNS); do
    kill_daemons

    T_START=$(now_ns)
    "$LIBS_DIR/.antirev-libd" 2>/tmp/antirev_bench_daemon.log
    T_END=$(now_ns)

    ms=$(elapsed_ms "$T_START" "$T_END")
    daemon_times+=("$ms")
    daemon_self_time=$(grep -oP 'in \K[0-9.]+(?=s)' /tmp/antirev_bench_daemon.log || echo "?")
    echo "    run $run: ${ms} ms (daemon self-report: ${daemon_self_time}s)"
done

DAEMON_STARTUP_MS=$(median "${daemon_times[@]}")
echo "    Median: ${DAEMON_STARTUP_MS} ms"
echo ""

# ──────────────────────────────────────────────────────────────────
# 4. Measure exe startup overhead
#    Daemon is running from last measurement.
# ──────────────────────────────────────────────────────────────────
echo ">>> [4/6] Measuring exe startup overhead..."

# Ensure daemon is running
kill_daemons
"$LIBS_DIR/.antirev-libd" 2>/dev/null
sleep 0.5

echo "    [4a] Protected noop exe (daemon mode, 0 DT_NEEDED on encrypted libs)..."
prot_times=()
for run in $(seq 1 $N_RUNS); do
    T_START=$(now_ns)
    "$OUT_DIR/exe_0001.protected" 2>/dev/null
    T_END=$(now_ns)
    prot_times+=("$(elapsed_ms "$T_START" "$T_END")")
done
EXE_PROT_MS=$(median "${prot_times[@]}")
EXE_OVERHEAD_MS=$(( EXE_PROT_MS - EXE_ORIG_MS ))
echo "    Protected noop exe median: ${EXE_PROT_MS} ms"
echo "    Exe startup overhead:      ${EXE_OVERHEAD_MS} ms"
echo ""

# ──────────────────────────────────────────────────────────────────
# 5. Measure lib link overhead
# ──────────────────────────────────────────────────────────────────
echo ">>> [5/6] Measuring lib link overhead (exe DT_NEEDED all ${N_LIBS} libs)..."

echo "    Protected linked exe (${N_LIBS} libs on LD_PRELOAD)..."
linked_prot_times=()
for run in $(seq 1 $N_RUNS); do
    T_START=$(now_ns)
    "$OUT_DIR/exe_linked.protected" 2>/dev/null
    T_END=$(now_ns)
    linked_prot_times+=("$(elapsed_ms "$T_START" "$T_END")")
done
LINKED_PROT_MS=$(median "${linked_prot_times[@]}")

LINK_OVERHEAD_RAW=$(( LINKED_PROT_MS - EXE_PROT_MS ))
LINK_OVERHEAD_ORIG=$(( LINKED_ORIG_MS - EXE_ORIG_MS ))
LINK_OVERHEAD_ANTIREV=$(( LINK_OVERHEAD_RAW - LINK_OVERHEAD_ORIG ))
echo "    Protected linked exe median: ${LINKED_PROT_MS} ms"
echo "    Link overhead (unprotected): ${LINK_OVERHEAD_ORIG} ms"
echo "    Link overhead (protected):   ${LINK_OVERHEAD_RAW} ms"
echo "    Extra link overhead from antirev: ${LINK_OVERHEAD_ANTIREV} ms"
echo ""

# ──────────────────────────────────────────────────────────────────
# 6. Memory overhead
# ──────────────────────────────────────────────────────────────────
echo ">>> [6/6] Measuring memory overhead..."

EXE_PROT_RSS=$(get_rss_kb "$OUT_DIR/exe_0001.protected")
LINKED_PROT_RSS=$(get_rss_kb "$OUT_DIR/exe_linked.protected")

kill_daemons
"$LIBS_DIR/.antirev-libd" 2>/dev/null
sleep 0.5
DAEMON_PID=$(pgrep -x '.antirev-libd' 2>/dev/null | head -1 || echo "")
if [ -n "$DAEMON_PID" ]; then
    DAEMON_RSS=$(awk '/VmRSS/{print $2}' "/proc/$DAEMON_PID/status" 2>/dev/null || echo "?")
else
    DAEMON_RSS="?"
fi

echo "    Daemon RSS:                 ${DAEMON_RSS} KB"
echo "    Noop exe RSS (orig):        ${EXE_ORIG_RSS} KB"
echo "    Noop exe RSS (protected):   ${EXE_PROT_RSS} KB"
echo "    Linked exe RSS (orig):      ${LINKED_ORIG_RSS} KB"
echo "    Linked exe RSS (protected): ${LINKED_PROT_RSS} KB"
echo ""

kill_daemons

# ──────────────────────────────────────────────────────────────────
# Results summary
# ──────────────────────────────────────────────────────────────────
echo "============================================================"
echo "  RESULTS SUMMARY"
echo "  ${N_LIBS} libs + ${N_EXES} exes, ~5 MB each"
echo "  Total data: $(( TOTAL_SIZE / 1048576 )) MB"
echo "============================================================"
echo ""
printf "%-45s %s\n" "Metric" "Value"
echo "------------------------------------------------------------"
printf "%-45s %s ms\n" \
    "1. Daemon startup (decrypt ${N_LIBS} libs)" "$DAEMON_STARTUP_MS"
printf "%-45s %s ms (%s → %s ms)\n" \
    "2. Exe startup overhead" "$EXE_OVERHEAD_MS" "$EXE_ORIG_MS" "$EXE_PROT_MS"
printf "%-45s %s ms\n" \
    "3. Lib link overhead (antirev extra)" "$LINK_OVERHEAD_ANTIREV"
printf "%-45s %s ms (orig: %s ms)\n" \
    "   Link overhead (protected, ${N_LIBS} libs)" "$LINK_OVERHEAD_RAW" "$LINK_OVERHEAD_ORIG"
echo ""
printf "%-45s %s ms\n" "Encryption time (${N_LIBS} libs)" "$ENC_LIBS_MS"
echo ""
printf "%-45s %s KB\n" "Daemon RSS" "$DAEMON_RSS"
printf "%-45s %s KB → %s KB\n" "Noop exe RSS (orig → prot)" \
    "$EXE_ORIG_RSS" "$EXE_PROT_RSS"
printf "%-45s %s KB → %s KB\n" "Linked exe RSS (orig → prot)" \
    "$LINKED_ORIG_RSS" "$LINKED_PROT_RSS"
echo "============================================================"
