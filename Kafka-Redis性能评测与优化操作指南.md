# Kafka / Redis 性能评测与优化操作指南

> 面向离线服务器数据链路 `板卡发送端 → Kafka → Python 消费 → Redis`。
> 用途:①评测 Kafka / Redis 当前性能上限与余量;②给出可落地的优化方向与操作步骤;③作为"是否切换集群模式 / 是否会丢消息"的判断依据。

---

## 目录
1. [评测总原则](#一评测总原则)
2. [Kafka 性能评测](#二kafka-性能评测)
3. [Redis 性能评测](#三redis-性能评测)
4. [余量计算与记录模板](#四余量计算与记录模板)
5. [优化方向 A:Kafka 发送端吞吐](#五优化方向-akafka-发送端吞吐)
6. [优化方向 B:Kafka 可靠性防丢消息](#六优化方向-bkafka-可靠性防丢消息)
7. [优化方向 C:Redis 吞吐与集群](#七优化方向-credis-吞吐与集群)
8. [决策与操作清单](#八决策与操作清单)

---

## 一、评测总原则

### 1. 木桶效应
整条链路是流水线,单机整体上限 = **最慢的那个环节**。必须分环节测,再定位瓶颈。

### 2. 必须用「真实参数」
用默认参数压出来的数字没有意义。评测前固定与生产一致的参数:

| 参数 | 说明 |
|---|---|
| 消息 / value 大小 | 平均字节数(大小消息瓶颈点不同) |
| Redis 命令类型 | SET 为主?还是 HSET / ZADD 等 |
| 是否 pipeline / 批量 | 对 Redis 上限影响可达 10 倍 |
| Kafka 分区数、acks | 分区数决定消费并行度上限 |

### 3. 上限判定标准(SLO)
"性能上限" = 满足以下条件时能**稳定持续**承受的最大吞吐:
- **Kafka consumer lag 不持续增长**(消费 ≥ 生产,lag 走平而非线性上涨)——核心指标
- 端到端延迟 p99 在可接受范围
- 无积压导致丢消息 / OOM

### 4. 重点看「单核 CPU」
Python 单进程(GIL)与 Redis 单实例都是**单线程吃单核**。总 CPU 可能才 20%,但某个核已 100% —— 这才是真瓶颈。逐核查看:
```bash
mpstat -P ALL 1
```

---

## 二、Kafka 性能评测

### 2.1 生产端极限吞吐(`--throughput -1` 不限速压到底)
```bash
kafka-producer-perf-test.sh \
  --topic <topic> \
  --num-records 5000000 \
  --record-size <真实消息字节数> \
  --throughput -1 \
  --producer-props bootstrap.servers=<broker:9092> acks=1
```
**记录**:`records/sec`、`MB/sec`、`avg latency`、`p99 latency` —— 写入天花板。

### 2.2 消费端极限吞吐
```bash
kafka-consumer-perf-test.sh \
  --bootstrap-server <broker:9092> \
  --topic <topic> --messages 5000000 --threads 1
```
**记录**:`nMsg.sec`、`MB.sec` —— 消费天花板。消费并行度受**分区数**限制。

### 2.3 实时观测消费是否跟得上(lag)
```bash
kafka-consumer-groups.sh --bootstrap-server <broker:9092> \
  --describe --group <消费组名>
```
盯 `LAG` 列:**走平 = 跟得上;持续增长 = 已超上限**。

### 2.4 当前实际生产速率(算余量用)
- JMX 指标 `MessagesInPerSec` / `BytesInPerSec`,或
- `GetOffsetShell` 观察 offset 增长速率折算

---

## 三、Redis 性能评测

### 3.1 基准吞吐(单条 vs pipeline 对比 —— 最关键一步)
```bash
# 单条(-P 1,贴近逐条写):
redis-benchmark -h <host> -p <port> -n 2000000 -c 50 -t set -d <真实value字节数> -P 1

# 批量(-P 16,贴近 pipeline 批写):
redis-benchmark -h <host> -p <port> -n 2000000 -c 50 -t set -d <真实value字节数> -P 16
```
**记录**:`requests per second`。两者差距 = pipeline 的提升空间。集群模式加 `--cluster`。

### 3.2 实时观测当前负载
```bash
redis-cli -h <host> -p <port> --stat                       # 每秒 ops、内存滚动刷新
redis-cli -h <host> -p <port> info stats | grep instantaneous_ops_per_sec
redis-cli -h <host> -p <port> info commandstats            # 各命令次数 + 平均耗时
redis-cli -h <host> -p <port> slowlog get 20               # 慢命令
```
> Redis 单实例单线程吃单核,配合 `mpstat -P ALL` 看其所在核是否到 100%(硬顶)。

---

## 四、余量计算与记录模板

真正有价值的结论是使用率:
```
使用率 = 当前实际峰值吞吐 / 实测上限
```
**示例**:实测 Redis 单实例上限 8 万 ops/s,当前峰值 6 万 → 使用率 75%,余量已很小 → 逼近该切集群模式的临界点。

| 组件 | 实测上限 | 当前峰值 | 使用率 | 先饱和的资源 |
|---|---|---|---|---|
| Kafka 生产 | ___ MB/s | ___ | ___% | 磁盘 / 网卡 |
| Kafka 消费 | ___ msg/s | ___ | ___% | 分区数 / CPU |
| Redis(单条) | ___ ops/s | ___ | ___% | 单核 CPU |
| Redis(pipeline) | ___ ops/s | — | — | — |

补充记录:消息/value 大小 `___` 字节;Kafka 分区数 `___`;消费组 `___`;Redis 形态 ☐ 单实例 ☐ 集群(3 主 3 备);测试时间/环境 `___`。

---

## 五、优化方向 A:Kafka 发送端吞吐

### 5.1 先定位:到底是谁慢?
| 现象 | 真实瓶颈 | 多开发送端有用吗 |
|---|---|---|
| 发送端 CPU/线程打满、send 阻塞 | 发送端自身 | 有用(先调优) |
| broker 分区少、写入排队 | Kafka 分区数 | ❌ 先加分区 |
| lag 一直涨但发送端不忙 | 下游消费端(Python/Redis) | ❌ 发送越快积压越多 |

> 判断:看发送端**单核 CPU** + `send` 是否阻塞;同时看 `--describe` 的 **LAG**。lag 涨而发送端不忙 → 问题在消费端。

### 5.2 先调优「单个发送端」(收益往往最大)
| 参数 | 建议 | 作用 |
|---|---|---|
| `batch.size` | 调大(32~64KB) | 批量发送,减少请求次数 |
| `linger.ms` | 调大(5~20ms) | 凑批,吞吐大幅提升 |
| `compression.type` | `lz4` / `zstd` | 压缩省网络和磁盘 |
| `acks` | 吞吐优先用 `1`(可靠优先见第六节) | 不等所有副本 |
| 发送方式 | **异步 + callback**,别逐条 `.get()` | 避免阻塞 |
| `buffer.memory` / in-flight | 适当调大 | 缓冲更多待发消息 |

一个调优后的 producer 常能到 10 万+ msg/s,**先做这步,很可能就不用多开**。

### 5.3 要多开发送端,必须满足两个前提
1. **同步增加 Kafka 分区数**:分区数不变 = 还是挤在同几个分区,并行度上不去。分区数需 ≥ 发送端/消费端并行度。
2. **确认下游能消化**:当前是单 Python 消费 + 单 Redis,发送端提速后若下游扛不住,只是把瓶颈从发送端搬到 Redis / lag。

### 5.4 注意顺序性
多开发送端 / 多分区会打乱**全局顺序**(Kafka 仅保证**同分区内**有序)。需要顺序时按 key 路由到固定分区。

---

## 六、优化方向 B:Kafka 可靠性防丢消息

### 6.1 发送端丢消息的典型场景
| 场景 | 为什么丢 | 防护 |
|---|---|---|
| `acks=0` | 发出去不管,broker 没收到也不知道 | 改 `acks=all` |
| `acks=1` | leader 写入即返回,未同步副本时 leader 挂 → 丢 | `acks=all` + 多副本 |
| 异步发送不处理 callback | 发送失败静默丢 | 处理 callback,失败重发 |
| 进程退出前没 flush | 消息还在内存缓冲区就退出 | 关闭前 `flush()`/`close()` |
| `retries=0` | 瞬时错误(选举/抖动)直接丢弃 | `retries` 设大 + `delivery.timeout.ms` |
| buffer 满 `max.block.ms` 超时抛异常 | send 抛错没接住 | 调大 `buffer.memory` + 捕获重发 |

### 6.2 ⚠️ 单节点 Kafka 是最大风险点
单 broker → `replication.factor` 只能是 1。此时 **`acks=all` 也没用**("所有副本"就它自己),一旦这台 broker 磁盘损坏/宕机/未刷盘断电,已收消息**全丢**。真要防住 broker 级丢失,须上多 broker(RF≥3)。

### 6.3 发送端「不丢消息」推荐配置
```properties
acks=all
enable.idempotence=true               # 幂等:重试不重复(自动保证 acks=all、retries>0)
retries=2147483647
delivery.timeout.ms=120000
max.in.flight.requests.per.connection=5
```
代码层:处理发送 callback 异常 + 进程退出前 flush/close。

### 6.4 broker 侧(需多节点才生效)
```properties
replication.factor=3
min.insync.replicas=2
unclean.leader.election.enable=false
```

> **端到端不丢 = 发送端(acks=all+幂等+重试+优雅关闭) × broker(多副本+min.insync.replicas) × 消费端(处理完再提交 offset)**,一段弱就会丢。

---

## 七、优化方向 C:Redis 吞吐与集群

### 7.1 先用 pipeline 批量写(最省事、收益最大)
Redis 单实例的瓶颈常在**每条一次网络往返**。在 Python 消费端把逐条 `SET` 改为**批量 pipeline**,通常提升数倍到十几倍——往往比直接扩容更划算(参照第 3.1 节单条 vs pipeline 的实测差距)。

### 7.2 单实例是单核,别指望多核
Redis 单实例单线程。单核到 100% 即硬顶,加内存/加核对单实例无用。此时选项:pipeline 减少往返 → 或切集群分摊。

### 7.3 何时切集群模式
当 **Redis 单实例使用率逼近上限(如 >70~80%)**,或写入量已超单实例天花板 → 切集群模式:3 台离线服务器、每台 1 主 1 备、共 3 主 3 备,按 slot 分片把写入分摊到 3 个主节点。

---

## 八、决策与操作清单

按顺序执行:

1. **定位瓶颈**:各环节单核 CPU + Kafka lag,先确认是发送端 / broker / 消费端 / Redis 哪一环。
2. **发送端慢** → 先按 5.2 调优单个 producer;不够再按 5.3 加分区 + 多开。
3. **担心丢消息** → 按第六节配 `acks=all`+幂等+重试+优雅关闭;并评估单节点 Kafka 加副本。
4. **Redis 慢** → 先上 pipeline 批量写(7.1);逼近上限再切集群(7.3)。
5. **Kafka 消费 lag 涨但分区少** → 加分区 + 提升消费并行度。
6. **全程确认下游能消化**:任何上游提速,都要先确认 Python + Redis 跟得上,否则只是转移瓶颈。

---

### 附:评测前需确认的信息
- 离线服务器 OS(Linux / Windows)与规格(CPU 核数、内存、磁盘类型、网卡)
- 消息 / value 平均大小、Redis 主要命令类型、是否已用 pipeline
- Kafka 分区数、消费组名、broker 地址;Redis host:port;当前模式(单实例 / 集群)
- 发送端语言、发送方式(同步/异步)、当前 `batch.size` / `linger.ms` / `acks` 配置
