# C++ aarch64 程序内存增长诊断 — 工作文档

> 工作类型:**进行中的诊断**(非结题报告)
> 跟踪分支:`xcc_memleak`
> 适用对象:跑在 aarch64 GPB 板上的 C++ 业务进程,默认 glibc ptmalloc,工具受限(无 bcc/heaptrack/valgrind)
>
> **方法论已抽取为通用 skill**:[`.claude/skills/cpp-memleak/SKILL.md`](../.claude/skills/cpp-memleak/SKILL.md) —— 约束驱动 + 多假设 + 交叉验证,可以对任意 C++ 程序的内存增长问题套用。本文档是它在**这个具体 case** 上的实例化记录。

---

## 1. 现象与背景

| 项 | 内容 |
|---|---|
| 平台 | Linux aarch64,GPB 板(嵌入式/服务器板) |
| 程序 | **`simultor`** — C++ plugin platform,通过 `dlopen` 加载业务 `.so`;本 case 加载 **4 个业务 plugin**,该组合 leak,其他 plugin 组合不漏(强烈暗示跨 plugin 互动 leak) |
| glibc 版本 | **2.34**(`ldd --version`)— ptmalloc struct offsets `next=2160 / attached_threads=2176 / system_mem=2184`(实验手册 R3.4.2 raw 偏移版用) |
| 现象 | RSS 持续增长 |
| 速率 | 昨天 17 GB,今天 21 GB,**~4 GB / 24 小时** |
| 板上可用工具 | gdb、pmap、grep、awk;**无** bcc-tools、heaptrack、valgrind、nproc |
| 源码可得 | ✅ 可做源码审查 |

---

## 2. 已收集的诊断数据

### 2.1 进程内存总览 (`/proc/$PID/status` + `smaps_rollup`)

```
VmPeak  62.8 GB
VmSize  62.8 GB
VmRSS   21.7 GB
Rss     21.7 GB
Pss     21.7 GB   ← 几乎等于 Rss,内存基本完全私有(共享页极少)
```

VSZ 与 RSS 差 41 GB:虚拟地址保留得多,实占少 → 配合 §2.2 看主要原因是 reserve 段。

### 2.2 段细分 (`pmap -x`)

按 RSS 排序后:

- **309 个 64 MB 的 `[anon]` 段,Size = RSS = Dirty = 65536 KB**(每段都 fully resident)
  - 合计 RSS = **19,776 MB ≈ 19.3 GB**
  - 占总 RSS **89%**
- 3 个大于 64 MB 的 `[anon]` 段:
  - `264644 KB virt / 185716 KB RSS`(258 MB / 181 MB,中等大对象/缓冲区)
  - `443736 KB virt / 435580 KB RSS`(433 MB / 425 MB,大对象/缓冲区,几乎全用)
  - `2150652 KB virt /    348 KB RSS`(2.05 GB / 0.34 MB,**典型 reserve 段**,虚预留没真用)
- `[heap]`、文件 mmap、`[stack]` 占比相对小

### 2.3 线程 (`/proc/$PID/task`)

| 时点 | 线程数 |
|---|---|
| T0 | 59 |
| T0 + 30s | 59 |

**线程数稳定,排除 thread leak**。

### 2.4 环境变量 (`/proc/$PID/environ`)

```
MALLOC_*  : 未设置
TCMALLOC_*: 未设置
LD_PRELOAD: 未设置
```

→ 使用 **默认 glibc ptmalloc**,无自定义 allocator。

### 2.5 CPU 与 ptmalloc arena 上限

- `grep -c ^processor /proc/cpuinfo` = **8**
- ptmalloc 默认 arena 上限(64 位):`8 × CPU = 8 × 8 = 64 arena`
- 59 线程 ≤ 64,基本"一线程一 arena"

### 2.6 `malloc_info` 关键数字

通过 gdb 注入 `malloc_info(0, FILE*)` 拿到的全局汇总:

```
<total type="fast" count="1241"   size="74,976">          ←   73 KB (fastbin 闲置)
<total type="rest" count="917015" size="491,529,703">     ←  469 MB (rest bin 闲置)
<total type="mmap" count="42"     size="697,929,728">     ←  665 MB (42 个直接 mmap 大块)
<system type="current"            size="21,656,682,496"> ← 20.17 GB
<system type="max"                size="21,656,682,496"> ← 20.17 GB (峰值=当前)
<aspace type="total"              size="21,656,682,496">
<aspace type="mprotect"           size="21,656,682,496">
```

---

## 3. 已得出的结论

### 3.1 排除的可能

| 假设 | 数据支持 | 结论 |
|---|---|---|
| Thread leak | 线程数 30 秒稳定在 59 | ✗ 排除 |
| ptmalloc 多 arena 纯浪费 / 不归还 | 闲置仅 469 MB / 20.17 GB = **2.3%** | ✗ 排除(利用率太高,不是浪费) |
| 自定义 allocator(tcmalloc/jemalloc) | 无 LD_PRELOAD,无相关 env | ✗ 排除 |
| 文件 page cache / 共享内存 | Pss ≈ Rss,共享基本为零 | ✗ 排除 |

### 3.2 已确定的事实

1. **ptmalloc 利用率 97.7%**(`(system - free) / system = (20.17 - 0.47) / 20.17`)
2. 业务**真正在持有**:`19.70 GB (ptmalloc) + 0.65 GB (大 mmap) ≈ 20.35 GB`
3. arena 结构:59 arena × 平均 5 subheap × 64 MB = ~308,与 pmap 看到的 309 个 64 MB 段一致
4. free 块 91.7 万个,绝大多数是小块 → 典型 C++ STL 容器(string、unordered_map、small object)分配 pattern
5. subheap **不是空的,塞满了真业务数据**

### 3.3 仍待区分的两种情形

| | (A) 真泄漏 | (B) 设计上的无界增长 |
|---|---|---|
| 机理 | `new` 没配对 `delete` / 异常路径漏 free / 容器装裸指针等 | 单调增长的 cache / 历史 buffer / log 队列 / metric / session map 等 |
| 修法 | 改代码,加 `delete` / 用 smart pointer / RAII | 加容量上限 / TTL / eviction;或确实需要,加资源监控 |
| 外部数据上的区分 | **不可区分**——两者都表现为"持续 alloc 没 free" |

→ **不论 (A) 还是 (B),都必须定位具体调用栈或源码位置**才能根治。

### 3.4 §4 snapshot diff 已 cross-verify 的结论(2026-06-03)

经过 T0 → T1 (69 min) snapshot 对比(见 §4.3):

1. **新增 RSS 100% 是 live 数据**(Δrest ≈ 0,Δsystem = ΔVmRSS = 3×64MB subheap)
2. **稳定线性增长** ~2.7 MB/min,符合最初 4 GB/天 观察
3. **完全排除**:线程泄漏、自定义 allocator、共享内存、文件 cache、ptmalloc 碎片化、ptmalloc 不归还
4. **剩余假说**(此时):long-lived 容器内的小对象单调累积(§3.3 中的 A 或 B)
5. **要解决的问题**:源码定位到具体的 long-lived 容器 + 写入路径

此结论已**交叉验证**(snapshot diff 法 + malloc_info 统计法 + smaps 段统计法 三种方法独立指向同一结论)。

### 3.5 Exp-A / Exp-B 实测(2026-06-04)— 画像重大修订

为防止源码审查方向走偏,按 `docs/cpp_memleak_constraint_experiments.md` 跑约束收窄实验。两组结果:

| 实验 | 结果 | 含义 |
|---|---|---|
| **Exp-A** per-arena `<system current>` 分布 | **max/avg = 45.9×** | 一个 arena 独占 RSS 的 70%+(约 **15-16 GB**),其余 58 个 arena 共担 ~5-6 GB |
| **Exp-B** 三个 > 64 MB 大段 ΔRSS | 三段稳定不变 | 增长**只来自新增 64 MB subheap**,确认"许多小对象累积"形态 |

**§3.4 第 4 条剩余假说被推翻**:原 "all-workers 稳态路径" 画像不成立。**单 arena 集中** ≠ 所有 worker 均匀贡献。

**修订后嫌疑画像**:

> **一个特定线程**(arena 0 = 主线程,或某 arena N>0 = 某单个 worker)在持续累积许多小对象(~512 B 量级),~每秒 90 次,合计 ~15-16 GB。**其余 58 个线程基本无辜**。

**剩余待确认**(决定下一步审查方向):

1. top arena 编号 = ?(0 → 主线程 leak;N>0 → 单 worker leak)
2. 若 N>0,该 arena 对应 tid = ?
3. 该 tid 的栈在做什么?

→ 通过 `cpp_memleak_constraint_experiments.md` **Round 2 — Exp-F (arena → thread 映射)** 解决。Exp-F 结果回填到本节末尾。

**Exp-F 结果区(待填)**:

| 项 | 值 |
|---|---|
| top arena 编号 | (待填) |
| top arena 地址 | (待填) |
| top arena system_mem | (待填) |
| 映射到 tid | (待填) |
| 该 tid 的栈顶 | (待填) |
| 该 tid 的入口 function | (待填) |

### 3.6 进程重启 — 调查转入重启诊断窗口模式(2026-06-04)

调查期间目标进程被重启,RSS 从 21 GB 回落到约 3 GB。

**前一轮(21 GB)数据仍然有效**作为独立观察(arena 集中 45.9×、大段稳定、3.88 GB/天速率);本轮(3 GB 起)按**重启诊断窗口** playbook 继续(见 `cpp_memleak_constraint_experiments.md` **Round 3 — 重启诊断窗口 playbook**)。

**两轮交叉验证逻辑**:

| 复现条件 | 含义 |
|---|---|
| T1/T2/T3 多时点显示 top arena 越来越集中,最终接近前一轮的 45.9× 集中度 | leak 行为**可复现且具普遍性**,前一轮结论成立 |
| 集中度始终保持 ≈ 1,即使 RSS 涨到 10 GB+ | 前一轮 45.9× 不是 leak 的本质,而是**进程多日老化的副产品** — 必须改回 all-workers 画像 |
| 增长速率与前一轮 (3.88 GB/天) 显著不同 | 业务负载不一样(可能有特定流量触发) — 需要标定 |
| 重启后 RSS 长期稳定不涨 | leak 是**特定环境/数据/时段**触发的偶发,而非普遍稳态 leak |

**第二轮 Exp-A/F 待填**:

| 时点 | RSS | max/avg | top arena | top arena tid | 该 tid 入口 |
|---|---|---|---|---|---|
| **T0** (实际是 +16h,2026-06-04 11:02) | ~3 GB | **45.2×** | **arena 55 = 2048 MB**(占 ~67%) | 候选 ∈ {36623, 36615, 36093} (Round 5 路径锁定) | (待三个 tid 的完整 bt) |

### 3.7 速率交叉验证(2026-06-04)— 排除 init-time 假说

**进程实际运行时间**:6/3 18:57 → 6/4 11:02 = **16 小时 5 分钟**(snapshot 不是"重启后立刻",而是已稳态运行 16 h)。

| 计算 | 数值 |
|---|---|
| Round 1 (21 GB 状态) 测得稳态速率 | 162 MB/h |
| 期望 runtime 累积:16 h × 162 MB/h | 2.6 GB |
| snapshot 时实际 RSS | 3 GB |
| **隐含 init baseline** | 3 − 2.6 = **0.4 GB**(合理 C++ 启动量) |
| **arena 55 累积速率** = 2 GB / 16 h | **125 MB/h ≈ 35 KB/s** |
| 若累积对象平均 500 B,则触发频率 | **~70 个对象/秒** |

**关键结论**:
1. **runtime-driven leak,不是 init-time**(原 init-time 假说从 ~30% 降到 ~10%)
2. **速率稳态非常硬**:两个独立观察(21 GB / 25 GB / 天 vs 0.4 → 3 GB / 16 h)给出几乎相同速率(167 vs 162 MB/h)
3. **嫌疑代码路径被 ~每秒 70 次** 触发(不算高频,匹配 simulator tick / RPC 请求 / 心跳报告 / 周期 metric)
4. **每次累积 ~500 B**(string、struct、protobuf message、连接 state 量级)

**对源码审查的精细化问题**(给内部模型):

- 4 plugin 里**哪个函数被 ~70 次/秒 触发**?
- 该函数**是否分配几百字节对象**?
- 这些对象**进了哪个 long-lived 容器**(plugin 内 / 平台共享 / 跨 plugin)?
| T1 (+6 h) | (待填) | (待填) | (待填) | (待填) | (待填) |
| T2 (+24 h) | (待填) | (待填) | (待填) | (待填) | (待填) |
| T3 (+48-72 h) | (待填) | (待填) | (待填) | (待填) | (待填) |

**T0 关键观察**(2026-06-04,新进程立刻采样):

| arena | sysmem | 占比 |
|---|---|---|
| **arena 55** | **2048 MB** | **~67%** |
| arena 0 (main) | 245.3 MB | ~8% |
| arena 62 | 50.0 MB | ~2% |
| arena 19 | 30.3 MB | ~1% |
| arena 23 | 24.1 MB | ~1% |
| 其余 ~50 arena | 共 ~600 MB | ~22% |

**结论**:
1. **集中模式立刻复现**(45.2× ≈ 前一轮的 45.9×),证明 leak 不是多日老化的副产品,**是结构性的**
2. **不是 main_arena(arena 0)主导** → 推翻"主线程在涨"假说,锁定 "某个 worker thread (arena 55)"
3. **重启后立刻 2 GB 在 arena 55** → 该线程**业务密集型 + 长持有**,可能是 init 阶段就分配了大量数据,或重启后流量恢复非常快
4. 审查范围已缩到 1 个 tid 的调用链 —— 大幅缩小

---

## 4. 当前执行的方案:**Snapshot Diff**(优先,不重启不干扰生产)

### 4.1 原理

预期:4 GB/天 ≈ 167 MB/小时 ≈ 多 2~3 个 64 MB subheap / 小时。
取两个时点的内存 snapshot 对比,看:

1. RSS 涨了多少
2. 多了哪些 64 MB subheap(地址)
3. `<system size>` 涨了多少(总申请增量)
4. `<total>` 涨了多少(闲置增量)
5. 线程数有没有变

**Δ(system) 与 Δ(total)** 的比例:

| Δ(system) | Δ(total free) | 含义 | 下一步 |
|---|---|---|---|
| ≈ ↑X | ≈ ↑X | 加分配的最后都进了 free 池 → ptmalloc 没归还 | 重启加 `MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=131072` |
| ↑X | 0 或 ↑ε | 真的有 X 字节数据进来没释放 → leak 或 unbounded growth | 走 §7 备选方案 + §5 源码审查 |
| 0 | 0 | RSS 涨但 ptmalloc 没涨 → 看 mmap 段、栈、shared anon | 看 `pmap` diff 哪个段长大 |

### 4.2 执行步骤

#### T0(现在)

```bash
PID=<填入>
SNAP_DIR=/tmp/mem_snap
mkdir -p $SNAP_DIR
T0=$(date +%Y%m%d_%H%M)
echo "PID=$PID, T0=$T0" > $SNAP_DIR/$T0.meta

# 1) RSS / VSZ
grep -E "VmRSS|VmSize|VmPeak" /proc/$PID/status > $SNAP_DIR/$T0.rss

# 2) pmap 全表(留着 forensics 用)
pmap -x $PID > $SNAP_DIR/$T0.pmap

# 3) 64 MB anon 段地址列表(排序后好做 set diff)
pmap -x $PID | grep anon | awk '$2 == 65536 {print $1}' | sort > $SNAP_DIR/$T0.subheaps

# 4) > 64 MB anon 段(看是不是有大对象池在长)
pmap -x $PID | grep anon | awk '$2 > 65536' > $SNAP_DIR/$T0.large

# 5) malloc_info(走 gdb 注入 fopen + malloc_info 写到文件)
gdb -batch -p $PID \
    -ex 'set $f = (void *)fopen("'$SNAP_DIR/$T0.mi'", "w")' \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)' \
    > $SNAP_DIR/$T0.gdb.log 2>&1

# 6) 线程数
ls /proc/$PID/task | wc -l > $SNAP_DIR/$T0.threads

echo "T0 snapshot: $SNAP_DIR/$T0.*"
```

#### T1(等 1 小时)

把上面所有命令重跑一遍,只把 `T0=$(date ...)` 改成 `T1=$(date ...)`,其余文件名替换。

#### Diff

```bash
SNAP_DIR=/tmp/mem_snap
T0=<T0 时间戳>
T1=<T1 时间戳>

echo "=== RSS / VSZ ==="
diff $SNAP_DIR/$T0.rss $SNAP_DIR/$T1.rss

echo "=== 64 MB subheap 数量 ==="
wc -l $SNAP_DIR/$T0.subheaps $SNAP_DIR/$T1.subheaps

echo "=== 新增的 64 MB subheap 地址 ==="
comm -13 $SNAP_DIR/$T0.subheaps $SNAP_DIR/$T1.subheaps

echo "=== 大于 64 MB 段对比 ==="
diff $SNAP_DIR/$T0.large $SNAP_DIR/$T1.large

echo "=== malloc_info 关键数字 ==="
for f in $T0 $T1; do
    echo "--- $f ---"
    grep -E 'system type="current|<total type=' $SNAP_DIR/$f.mi
done

echo "=== 线程数 ==="
echo "T0:"; cat $SNAP_DIR/$T0.threads
echo "T1:"; cat $SNAP_DIR/$T1.threads
```

### 4.3 结果记录区(已填,T0 → T1 = 69 min)

| 项 | T0 | T1 | Δ |
|---|---|---|---|
| VmRSS | 21,929,824 KB ≈ 21.42 GB | 22,120,384 KB ≈ 21.61 GB | **+186 MB** |
| 64 MB subheap 数 | 311 | 314 | **+3**(= 192 MB,与 ΔRSS 吻合) |
| `<system current>` | 21,747,040,256 B ≈ 20.25 GB | 21,942,280,192 B ≈ 20.44 GB | **+186 MB** |
| `<aspace total>` | 21,747,040,256 B | 21,942,280,192 B | +186 MB(同上) |
| `<total rest>` count | 917,015 | 917,038 | +23(几乎不变) |
| `<total rest>` size | 491,522,631 B ≈ 469 MB | 491,511,726 B ≈ 469 MB | **−0.01 MB**(反而轻微缩小) |
| `<total fast>` count | 1,249 | 1,186 | −63 |
| `<total fast>` size | 75,264 B | 72,288 B | −2.9 KB |
| 大于 64 MB 的 anon 段对比 | (3 段,见 §2.2) | 同 T0 | **无新增** |
| 线程数 | 59 | 59 | 0 |

**判读结论(对照 SKILL.md Phase 4 snapshot-delta decision matrix 第 1 行)**:

- Δsystem(+186 MB)≈ Δsubheap × 64 MB(+192 MB)≈ ΔVmRSS(+186 MB),三个数字两两吻合到 < 4%
- Δrest 实际为 **−0.01 MB**(free 池没有任何增长)
- 无 > 64 MB 新增段(排除单次大对象 mmap)
- 线程数不变(排除 thread leak / stack 增长)

→ **100% 的新增 RSS 全部进入"live 业务数据"**。碎片化假说彻底排除,allocator 不归还假说排除。

**速率**:69 min → +186 MB → **2.7 MB/min ≈ 162 MB/h ≈ 3.88 GB/天**,与最初观测 "17 GB → 21 GB / 一天" 完全一致。

**活数据量**:`<system current> - <total rest> - <total fast>` ≈ **20.97 GB**,即 C++ 进程中**真实正在引用、不可释放**的对象总量。

**下一步**:已无需更多外部诊断,直接进入 §5 / 交接文档 `cpp_memleak_source_review_handoff.md`,把约束交给有源码的 reviewer / 内部模型做语义分析。

---

## 5. 源码语义分析 Skill(约束驱动)

> **设计原则**:不做 grep 式机械模式匹配,而是把 §1-3 已得到的诊断画像**作为代码必须满足的约束**,用语义理解(由懂 C++ 的人或 LLM 执行)在源码里找符合约束的具体位置。
>
> 语义分析比 grep 强在三点:① 能区分"形似但实际无关"的代码(同名函数、注释里的关键字);② 能跨调用边界看"语义上的对称"(insert 跟 erase 是不是真的对称);③ 能基于诊断数字(比如 460 KB/s)给嫌疑点定**速率证据**,排序更准。

### 5.1 把诊断现象翻译成"嫌疑代码必须满足的画像"

每个诊断事实推导成一条对嫌疑代码的**约束**。代码必须同时满足所有约束,否则被排除。

| 诊断事实(来自 §2-3) | 推导出的代码约束 |
|---|---|
| 19.7 GB **业务真数据在持有**,利用率 97.7% | 嫌疑代码必然包含一个或多个 **long-lived 容器 / 持久持有结构**,不是局部变量 |
| **91.7 万 个 small free chunk**(平均块大小 ~512 B) | 累积的**对象很小**:`std::string`、节点式容器的 node、shared_ptr 的 control block、struct 几十/几百字节量级。**排除大 buffer 类(数 KB 以上单对象)** |
| **4 GB/天 ≈ 460 KB/秒** ≈ 每秒分配 ~900 个 ~512 B 对象不释放 | 嫌疑代码在**稳态业务路径**上,被高频触发(每秒至少几十次到几百次)。**排除冷路径**(配置加载、错误处理、初始化) |
| **59 线程稳定**,arena 数 ≈ 线程数,每 arena ≈ 5 subheap | 每个 worker 线程都贡献,**leak 是平均分布的**,不是个别 worker / 个别业务路径的 bug → 嫌疑代码在**所有 worker 都路过的共享逻辑**里 |
| 涨势**稳态、无突变** | **不是事件触发型**(reconnect 风暴、配置 reload、burst 入流);是稳定业务流量自身贡献 |
| Pss ≈ Rss(几乎全私有内存) | 跟**共享内存 / mmap 公共文件 / page cache 无关**,排除这些方向 |
| `<total type=mmap>` 仅 665 MB / 42 块(平均 16 MB) | 直接 mmap 的大对象**不是主要矛盾**,可以最后看 |

**合并以上,嫌疑画像总结**:

> 所有 worker 线程都路过的、被 ~每秒几百次触发的稳态业务路径里,有一个或多个 long-lived 容器(static / singleton 成员 / manager 成员 / thread_local),持续 push 进**小对象**(~512 B 量级),没有匹配的清理路径。

### 5.2 优先排查位置(根据画像精准定位)

**不是 grep**,而是回答"哪些代码块语义上符合上面的画像"。

#### 5.2.1 "所有线程路过的稳态路径"通常是:
- 主事件循环 / 消息分发 / 协程调度器 的 dispatch 函数
- worker thread 的 `run()` / `loop()` 入口
- 中间件 / 拦截器 / handler chain 的入口
- 协议解析器的 main entry
- RPC server 的 request handler

→ **从这些点开始往下追**,看每次 dispatch 路径上有没有"对 long-lived 容器的写入"。

#### 5.2.2 "long-lived 容器"具体识别:
| 形态 | 怎么找(语义识别) |
|---|---|
| 静态成员变量 | 类定义里 `static T member` 且 T 是容器/智能指针/裸指针 |
| namespace-level 全局 | `.cpp` 文件顶部的非 const 容器变量 |
| Singleton 类的成员 | Singleton/Manager/Registry 类的实例变量 |
| 长期存活 manager 的成员 | 在 `main()` 早期 new、在 shutdown 前永不 delete 的对象的成员 |
| thread_local 容器 | `thread_local std::xxx<T>` 在 .cpp/.h 里 |
| 通过 unique_ptr / shared_ptr 长期持有的对象 | 持有方是上述任意一种 |

→ 一个 long-lived 容器的**寿命**等于它的持有者的寿命。

#### 5.2.3 "insert / erase 不对称"的语义比对:
对每个 candidate 容器,执行:

1. 找到**所有写入**(`insert / emplace / push_back / operator[] = / try_emplace / merge`)
2. 找到**所有移除**(`erase / clear / pop_front / pop_back / extract / reset()`)
3. 评估两侧的**调用频率**和**触发条件**
4. 比较**频率比**:
   - 写入比移除频繁 1000:1 以上 → 高嫌疑
   - 写入在 hot path,移除在 destructor / shutdown → 高嫌疑
   - 写入和移除频率接近,但移除有 "if (some_condition)" → 看 condition 触发率
5. 如果有 "eviction strategy" 类的代码(LRU、TTL、size cap),**评估它是否真的会触发**(配置的阈值是不是太大,LRU 是不是基于业务很少触发的边界条件)

### 5.3 关键嫌疑模式分类(C++ 业务里 80% leak 落在这里)

每条模式给出**画像匹配度**(哪些诊断约束对得上)+ **怎么从源码识别**。

#### Pattern A:`unordered_map<Key, BigValue>` 单调增长
- **画像匹配**:long-lived ✓,小到中等对象 ✓,稳态写入 ✓
- **典型场景**:metric 聚合 by key、user/session map、cache 无 TTL
- **识别**:找类型 `std::(unordered_)?map<...>` 的成员,看它的 insert/emplace 在哪些方法被调,erase 在哪些方法被调,频率对比
- **快速验证**:如果能拿到那个 map 的 .size(),看是不是异常大

#### Pattern B:`vector<T*>` 装裸指针,容器析构不删指针
- **画像匹配**:long-lived ✓,小对象 ✓,稳态 ✓
- **典型场景**:工厂/registry 模式遗留的 C 风格代码、迁移到 C++ 一半的库
- **识别**:`std::vector<T*> v; v.push_back(new T())` 在 hot path,容器是 long-lived
- **快速验证**:`vector::size()` 单调增,但容器内对象数据流不再访问

#### Pattern C:shared_ptr 循环引用
- **画像匹配**:long-lived ✓,大量 control block(small chunk)✓,稳态 ✓
- **典型场景**:Session 持有 shared_ptr<Connection>,Connection 通过 callback 持有 shared_ptr<Session>
- **识别**:任何 `shared_ptr<A>` 成员在 A 自己或 A 的成员的另一个 `shared_ptr<...>` 链路里被持有
- **快速验证**:对 A 的 use_count() 跟踪,看它会不会归零

#### Pattern D:Callback / Observer 注册没注销
- **画像匹配**:long-lived(broker 持有)✓,小对象(closure / function 对象)✓,稳态 ✓
- **典型场景**:`event_bus.subscribe(this, handler)` 在 hot path,destructor 里漏 `unsubscribe`,或者异常路径跳过
- **识别**:`subscribe / register / addListener / on(...)` 的调用站点,看对面有没有等量的 `unsubscribe / remove / off`
- **快速验证**:event_bus 的 subscriber 数单调增

#### Pattern E:thread_local 容器
- **画像匹配**:每线程都贡献 ✓(完美匹配 "59 线程平均贡献" 这条约束)
- **典型场景**:`thread_local std::vector<Stat> g_stats` 用于线程局部统计,但永远不 reset
- **识别**:所有 thread_local 变量都列出来,看是不是容器,有没有 size 上限
- **快速验证**:`pthread` 级别的 RSS 趋势是不是相对均匀的

#### Pattern F:第三方库已知 leak 点
| 库 | 已知 leak / 累积点 |
|---|---|
| protobuf | `Arena` 没 Reset;`Message::set_*` 反复调没释放旧 |
| libcurl | `CURL` handle 没 `curl_easy_cleanup`;multi handle 没 `curl_multi_cleanup` |
| OpenSSL | `SSL_CTX` session cache 默认无上限;`X509` 链没 free |
| log4cxx / spdlog | 异步 logger 的 buffer 是否会归还 |
| RapidJSON / nlohmann::json | Document 反复 Parse 不 Clear |
| Boost.Asio | strand / timer / io_context::work 持有 |

→ 对每个引入的第三方库,**单独评估**它的"长期持有结构"是不是有清理路径。

### 5.4 调用 Skill 的方式

#### 给 LLM 用的 prompt 模板

```
你是一位有经验的 C++ 内存问题调查者。下面是已经做完的内存现场诊断,
然后是待审查的源码文件。请基于诊断结果,做语义分析(不做 grep),
找出最符合诊断画像的嫌疑代码点。

## 已知诊断画像(约束)
- 平台:aarch64,默认 glibc ptmalloc
- 现象:RSS 持续涨,~4 GB/天 = 460 KB/秒
- ptmalloc 利用率 97.7%(业务真持有 19.7 GB,不是碎片)
- ~91.7 万 small free chunk(平均块 ~512 B)→ 累积的是小对象
- 59 线程稳定,每个 arena 平均 5 subheap → leak 平均分布,所有 worker 贡献
- 涨势稳态 → 不是事件触发,是稳定业务流量
- Pss ≈ Rss → 跟共享内存无关

→ 嫌疑画像:所有 worker 线程都路过的稳态路径里,有 long-lived 容器
   在被高频(~每秒数百次)推入小对象(~512 B),且没有匹配的清理路径

## 任务
对附上的源码文件,做以下分析:

1. **识别 long-lived 容器**:
   列出所有 static 成员、namespace 全局、Singleton/Manager 成员、
   thread_local 的容器/智能指针。

2. **对每个候选容器,列出 insert/emplace 点 + erase/clear 点,做对称性比对**:
   - 写入调用站点(文件:行 + 触发条件 + 估算调用频率)
   - 移除调用站点(同上)
   - **频率比 / 触发条件** 是否对称?

3. **评估每个嫌疑点是否符合 460 KB/秒的累积速率**:
   - 如果是 unordered_map<string, X>,每 insert 一项 ~多少字节?
   - 实际触发频率(估算)× 单项字节数 ≈ ?
   - 接近 460 KB/秒(±一个量级)才是强嫌疑

4. **跟 §5.3 的 Pattern A-F 对照**,如果命中某 pattern 直接标注

5. **给嫌疑度排序**,列前 5 个:
   | 排名 | 文件:行 | 命中 pattern | 累积速率估算 | 修法建议 |

要求:
- 不要做 grep 式报告(列一堆文件名没分析)
- 每个嫌疑点要有"为什么符合画像"的具体推理
- 排除画像不符的(大 buffer 类、冷路径类、非 long-lived 类)
```

#### 给人工 reviewer 用的 checklist

按 §5.2 顺序走:

- [ ] (5.2.1) 列出 3-5 个"所有线程路过的稳态入口函数",写在下面:
  ```
  - file.cpp:NNN  func_name  (描述: ...)
  - ...
  ```
- [ ] (5.2.2) 列出所有 long-lived 容器(分形态)
- [ ] (5.2.3) 对每个 long-lived 容器,做 insert/erase 对称性分析
- [ ] (5.3) 对照 Pattern A-F,每个 pattern 评估是否在本代码库出现
- [ ] (5.4) 把嫌疑点按本节末尾的"嫌疑登记表"格式记录

### 5.5 嫌疑代码登记(分析结论写在这)

| 排名 | 文件:行 | 嫌疑容器 | 命中 pattern | insert 频率 | erase 触发率 | 估算累积速率 | 是否符合 460 KB/s | 推荐修法 | 状态 |
|---|---|---|---|---|---|---|---|---|---|
| (待填) | | | | | | | | | |

### 5.6 静态分析工具(辅助,不替代上面的语义分析)

静态分析适合**先扫一遍**找潜在线索,**但不能替代** §5.1-5.4 的约束驱动分析(它们不知道你的诊断画像)。

```bash
# cppcheck
cppcheck --enable=all --inconclusive --suppress=missingIncludeSystem \
         -j4 --output-file=/tmp/cppcheck.log <SRC>

# clang-tidy
clang-tidy -checks='cppcoreguidelines-*,bugprone-*,modernize-use-smart-ptr' \
           -p <build_dir> <SRC>/*.cpp 2>&1 | tee /tmp/clang_tidy.log
```

关注的检查项:
- `cppcoreguidelines-owning-memory`
- `bugprone-use-after-move`
- `modernize-use-smart-ptr`

把这些工具的结果**作为 §5.4 prompt 的额外输入**,让 LLM/人工 reviewer 在做语义分析时同时参考。

---

## 6. 备选方案(snapshot diff 后看情况启用)

### 6.1 方案 2:`MALLOC_ARENA_MAX=2` 重启验证(便宜)

**适用**:snapshot diff 显示 Δ(system) ≈ Δ(total free),即"分配后变 free 但 ptmalloc 没归还"。

```bash
MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=131072 ./your_prog
```

跑 24 小时观察:
- RSS 显著降 + 涨势缓和 → 实锤是 ptmalloc 浪费,**部署侧加 env 解决,无需改代码**
- 涨势依旧 → 真有数据累积,走方案 6.2

### 6.2 方案 3:自编 LD_PRELOAD allocator wrapper(下次重启窗口)

**适用**:确认是真累积(snapshot 显示 Δ(system) 远大于 Δ(total free)),需要 stack trace 定位。

~120 行 C 代码,板上 gcc 直接编。核心思路:

```
- wrap malloc / free
- 每次 malloc 调 backtrace() 取栈
- 用 stack 顶帧地址哈希,聚合"未释放字节数"到固定大小桶
- 用 ptr -> bucket 的小哈希表;free 时减回桶字节数
- SIGUSR1 触发 dump:把所有 outstanding > 1 MB 的桶 + stack 输出到 /tmp/alloc_track.<pid>
```

需要决策:
- backtrace 深度(默认 6 层,C++ 容器/智能指针场景可能要 10)
- dump 触发方式(信号 / 定时 / 退出)
- 阈值(多少字节以下不记录,避免开销)

代码模板待补充,执行前先把上述决策定下来。

### 6.3 方案 4:`gcore` + 离线分析(最稳但需 dev 机)

```bash
ulimit -c unlimited
gcore -o /tmp/myapp $PID    # 产出 ~21 GB 文件,进程冻几十秒
scp /tmp/myapp.$PID dev-machine:
# 在 dev 机:
gdb /path/to/your_prog /tmp/myapp.$PID
```

适合**当前进程状态太重要不能重启,且方案 1 + 5 不够**的时候。

### 6.4 方案 5:换 jemalloc + profiling(需自编 jemalloc)

```bash
# 一次性编译 jemalloc with --enable-prof
LD_PRELOAD=$JEMALLOC \
MALLOC_CONF='prof:true,prof_active:true,prof_prefix:/tmp/jeprof,lg_prof_interval:30' \
./your_prog
# 分析:
jeprof --text ./your_prog /tmp/jeprof.<pid>.<seq>.heap
```

适合**有时间 / 板上能装 jemalloc**,且想要更彻底的 profile。换 allocator 本身也可能改变 RSS 行为(jemalloc 通常更激进归还内存)。

---

## 7. 时间线 / 已采取动作

| 时间 | 动作 | 结果 |
|---|---|---|
| YYYY-MM-DD HH:MM | T0 snapshot | (待填) |
| YYYY-MM-DD HH:MM | T1 snapshot(预期 T0+1h) | (待填) |
| | snapshot diff 判读 | (待填) |
| | 源码扫描 §5.1 | (待填) |
| | 方案 2 / 3 / 4 决策 | (待填) |

---

## 8. 决策树(快速导航)

```
开始
 │
 ├─ §4 跑 snapshot diff(必做,1 小时)
 │      │
 │      ├─ Δ(system) ≈ Δ(total free)
 │      │      → §6.1 重启加 MALLOC_ARENA_MAX=2 验证
 │      │            ├─ 涨势缓和 → 部署侧固化 env,收工
 │      │            └─ 还涨    → 走真 leak 分支
 │      │
 │      ├─ Δ(system) ≫ Δ(total free)(真 leak / 无界增长)
 │      │      → §5 源码扫描 + §6.2 LD_PRELOAD profiler 双管齐下
 │      │
 │      └─ Δ(RSS) > Δ(system + mmap)(不在 ptmalloc 里的增长)
 │             → 看 pmap diff 哪段长大,定位段类型
 │
 └─ §5 同步进行(独立于 snapshot)
        ├─ §5.1 grep 扫嫌疑模式
        ├─ §5.2 7 题自问
        ├─ §5.3 cppcheck / clang-tidy 跑一遍
        └─ §5.4 嫌疑清单回填到本文档
```

---

## 附录 A:本次诊断已用过的命令清单

```bash
# 进程总览
grep -E "VmPeak|VmSize|VmRSS" /proc/$PID/status
cat /proc/$PID/smaps_rollup

# 段细分 / 64 MB 段统计
pmap -x $PID | grep anon | awk '$2 == 65536' | wc -l
pmap -x $PID | grep anon | awk '$2 == 65536 {sum += $3} END {print sum/1024/1024 " GB"}'
pmap -x $PID | grep anon | awk '$2 > 65536'

# 线程
ls /proc/$PID/task | wc -l

# 环境
cat /proc/$PID/environ | tr '\0' '\n' | grep -iE 'MALLOC|LD_PRELOAD|TCMALLOC'

# CPU
grep -c ^processor /proc/cpuinfo

# malloc_info(走 gdb,因为进程 stderr 不一定可读)
gdb -batch -p $PID \
    -ex 'set $f = (void *)fopen("/tmp/mi.xml", "w")' \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)'
```

---

## 附录 B:数字快算

- 64 MB = 65,536 KB(`pmap -x` 第二列匹配)
- ptmalloc 默认 arena 上限(64 位):`8 × n_cpu`
- ptmalloc 大对象 mmap 阈值:默认 128 KB(可调:`M_MMAP_THRESHOLD`)
- 大对象阈值以上的 malloc 走 mmap,不进 arena
- `MALLOC_TRIM_THRESHOLD_`(注意尾随下划线):heap 顶 free 块超过此值才会 sbrk(-) 还给 OS

---

> 文档维护:每次跑 snapshot / 源码扫描 / 启用备选方案,更新 §4.3、§5.4、§7 三个登记区。
