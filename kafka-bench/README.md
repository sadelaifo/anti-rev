# Kafka 发送端(librdkafka-C++)性能上限压测

测出你们 librdkafka-C++ 发送端的真实吞吐上限,并与"基础设施上限"对比,定位瓶颈在**客户端配置**还是**基础设施**。

---

## 1. 依赖与编译

需要 librdkafka(含 C++ 库)。

```bash
# 安装(二选一)
sudo apt-get install -y librdkafka-dev        # Debian/Ubuntu
# 或从源码编译 https://github.com/confluentinc/librdkafka

# 编译本工具
g++ -O2 -std=c++17 kafka_producer_bench.cpp -o kafka_producer_bench \
    -lrdkafka++ -lrdkafka -lpthread
```
> Windows 下用 vcpkg 装 librdkafka,再用 MSVC/MinGW 链接 `rdkafka++`、`rdkafka`。核心逻辑跨平台。

---

## 2. 准备 topic(分区数在这里定)

分区数不是 producer 参数,是 topic 属性。要扫描分区数,就建多个不同分区数的 topic:

```bash
kafka-topics.sh --bootstrap-server <broker:9092> --create \
  --topic bench_p6 --partitions 6 --replication-factor 1
```

---

## 3. 两个"上限"分别怎么测

| 上限 | 含义 | 怎么跑 |
|---|---|---|
| **A 基础设施上限** | broker+分区+网络+盘 的天花板 | 本工具用**激进调优参数**跑(见 run_sweep 第 1 项),或用官方 `kafka-producer-perf-test.sh` |
| **B 发送端现状上限** | 你们**当前配置**能发多快 | 本工具用**你们生产的实际 -X 参数**跑(run_sweep 第 0 项) |

**判定:**
- `B ≪ A` → 瓶颈在**客户端配置/实现**(优化空间大)
- `B ≈ A` → 瓶颈在**基础设施**(加分区 / 加 broker / 换盘)

---

## 4. 直接用法

```bash
# 现状上限 B:换成你们生产实际的配置
./kafka_producer_bench -b <broker:9092> -t bench_p6 -s <消息字节数> -c 5000000 \
    -X acks=1 -X linger.ms=0 -X compression.codec=none

# 基础设施上限 A:激进调优
./kafka_producer_bench -b <broker:9092> -t bench_p6 -s <消息字节数> -c 5000000 \
    -X acks=1 -X linger.ms=10 -X compression.codec=lz4 \
    -X batch.num.messages=100000 -X queue.buffering.max.messages=2000000

# 复现线上"丢消息":满即丢弃并计数(-D),缓冲区调小更容易触发
./kafka_producer_bench -b <broker:9092> -t bench_p6 -s <消息字节数> -T 60 -D \
    -X queue.buffering.max.messages=100000
```

一键扫描:
```bash
chmod +x run_sweep.sh
BROKERS=<broker:9092> TOPIC=bench_p6 MSGSIZE=<字节数> COUNT=5000000 ./run_sweep.sh
```

---

## 5. 怎么读结果

运行中每 2 秒输出一行:
```
[  10s] 已投递=1234567  速率=520000 msg/s (508.8 MB/s)  失败=0  队列积压=98456  丢弃=0
```
- **速率(msg/s、MB/s)**:取**稳态时**的值 = 该配置下的发送上限
- **队列积压(outq)**:持续贴近 `queue.buffering.max.messages` = 发送跟不上生产(缓冲在堆积)
- **失败 / 丢弃 > 0**:正在丢消息的直接证据

末尾 `==== 结果 ====` 给平均吞吐汇总。

---

## 6. 参数对照(Java 名 → librdkafka 名)

你们是 librdkafka,配置键用 **librdkafka 名**(通过 -X 传):

| 作用 | Java 客户端 | librdkafka(-X 用这个) | 默认 |
|---|---|---|---|
| 凑批时间 | linger.ms | `linger.ms`(别名 queue.buffering.max.ms) | 5ms |
| 批量字节 | batch.size | `batch.size` | 1000000 |
| 批量条数 | — | `batch.num.messages` | 10000 |
| 压缩 | compression.type | `compression.codec` | none |
| 确认级别 | acks | `acks`(别名 request.required.acks) | -1(all) |
| 发送缓冲(条数) | ~buffer.memory | `queue.buffering.max.messages` | 100000 |
| 发送缓冲(KB) | buffer.memory | `queue.buffering.max.kbytes` | 1048576 |
| 幂等 | enable.idempotence | `enable.idempotence` | false |
| 单连接在途请求 | max.in.flight... | `max.in.flight` | 1000000 |

---

## 7. 记录模板

| 项 | 配置 | msg/s | MB/s | p99 | 队列积压 | 失败/丢弃 |
|---|---|---|---|---|---|---|
| A 基础设施上限 | tuned | | | | | |
| A 分区扫描 1/3/6 | | | | | | |
| B 发送端现状 | 你们实际 | | | | | |
| 生产峰值 | 实际业务 | | | | — | — |

**结论:**
- 产能缺口 = 生产峰值 − B
- 优化天花板 = A − B
- 若 (A − B) ≥ 缺口 → 调优发送端即可;否则需扩基础设施(加分区/broker)

---

## 8. 注意事项(保证测出来有效)

- 在**发送端同一台机器**上跑,连**同一 broker**,用**真实消息大小**
- 跑够量(几百万条/数分钟),取**稳态**值,别用突发峰值
- 同时监控:发送端**单核 CPU**(`mpstat -P ALL 1`)、broker `BytesInPerSec`/请求队列/磁盘
- 一次只改**一个参数**(单变量),才能看清每项的影响
