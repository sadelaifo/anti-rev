#!/usr/bin/env bash
# 发送端上限参数扫描脚本
# 用法: BROKERS=10.0.0.1:9092 TOPIC=bench MSGSIZE=1024 COUNT=5000000 ./run_sweep.sh
set -uo pipefail

BROKERS="${BROKERS:-localhost:9092}"
TOPIC="${TOPIC:-bench}"
MSGSIZE="${MSGSIZE:-1024}"
COUNT="${COUNT:-5000000}"
BIN="${BIN:-./kafka_producer_bench}"

run() {
  local name="$1"; shift
  echo "======== $name ========"
  "$BIN" -b "$BROKERS" -t "$TOPIC" -s "$MSGSIZE" -c "$COUNT" "$@" \
    | grep -E "avg_throughput|delivered|failed|dropped|config"
  echo
}

echo ">> broker=$BROKERS topic=$TOPIC 消息大小=${MSGSIZE}B 每轮=${COUNT}条"
echo

# ---- 0) 基线:接近你们当前配置(把下面 -X 换成你们生产实际值) ----
run "0. 现状基线(改成你们的实际配置)" \
    -X acks=1 -X linger.ms=0 -X compression.codec=none

# ---- 1) 基础设施上限:激进调优,代表任何客户端的天花板 ----
run "1. 基础设施上限(tuned)" \
    -X acks=1 -X linger.ms=10 -X batch.num.messages=100000 \
    -X batch.size=1000000 -X compression.codec=lz4 \
    -X queue.buffering.max.messages=2000000 -X queue.buffering.max.kbytes=2097151

# ---- 2) 单变量扫描:linger.ms(凑批时间) ----
for v in 0 5 10 50; do
  run "linger.ms=$v" -X acks=1 -X linger.ms=$v -X compression.codec=lz4
done

# ---- 3) 单变量扫描:compression(压缩) ----
for v in none lz4 zstd snappy; do
  run "compression=$v" -X acks=1 -X linger.ms=10 -X compression.codec=$v
done

# ---- 4) 单变量扫描:acks(可靠性 vs 吞吐) ----
for v in 1 all; do
  run "acks=$v" -X acks=$v -X linger.ms=10 -X compression.codec=lz4
done

# ---- 5) 单变量扫描:批量条数 ----
for v in 1000 10000 100000; do
  run "batch.num.messages=$v" -X acks=1 -X linger.ms=10 \
      -X compression.codec=lz4 -X batch.num.messages=$v
done

echo ">> 分区扫描请对不同分区数的 topic 分别设置 TOPIC 再跑本脚本"
