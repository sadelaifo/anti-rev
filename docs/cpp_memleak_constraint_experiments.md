# 约束收窄实验手册 — 在源码审查之前/同时做

> **位置**:`cpp-memleak` skill 的 Phase 2-3 之间;handoff 文档的 §3 约束**收紧/可能修订**的依据。
> **触发场景**:Phase 0-1 已完成、已得出"long-lived 容器 + 小对象 + 漏清理"类初步画像,但**还没把源码交给审查方之前**,有必要再做一次廉价的多假设交叉验证,避免画像收得过紧导致内部审查走错方向。
> **执行条件**:板上有 `gdb`、`pmap`、`awk`、`grep` 即可。**全程不重启,不改业务代码**。

---

## 0. 为什么要做这个手册

初步画像是经验先验,数据并未把它**强制**到唯一形态。同样符合 Phase 0 数据的替代假说还有:

- **Alt-1** 单个长对象在长大(string `+=`、vector append、tree 不剪枝)
- **Alt-2** 业务自管理 memory pool / arena 自身在涨
- **Alt-3** 异步队列背压(consumer < producer)
- **Alt-4** 清理路径存在但触发条件不命中(TTL 太大、定时器没注册成功)
- **Alt-5** 非 `shared_ptr` 的循环引用
- **Alt-6** 第三方库内部累积(gRPC cache、protobuf descriptor、ODBC pool)
- **Alt-7** dlopen 反复加载 .so 不卸载
- **Alt-8** 注册激增(每次正常调用就 subscribe 一次)

下面 5 个实验用最低成本进一步约束,把画像锁到具体形态后再让审查方扫源码。

---

## 1. 同步采集 T0 / T1 snapshot

```bash
PID=<填进程 PID>
T=$(date +%Y%m%d_%H%M)              # T0 / T1 各跑一次
SNAP=/tmp/mem_snap/$T
mkdir -p $SNAP

# Exp-A: malloc_info(走 gdb 注入)
gdb -batch -p $PID \
    -ex "set \$f = (void *)fopen(\"$SNAP/mi.xml\", \"w\")" \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)' > /dev/null 2>&1

# Exp-B: pmap 完整 + 大段提取
pmap -x $PID > $SNAP/pmap.full
awk '$2 > 65536 {print $1, $2, $3}' $SNAP/pmap.full | sort > $SNAP/big_segs.txt

# Exp-D: 所有线程 backtrace
gdb -batch -p $PID -ex 'set pagination off' \
    -ex 'thread apply all bt 8' -ex 'detach' > $SNAP/threads.bt 2>&1

# Exp-E: 当前加载的 .so 列表
awk '/\.so/{print $NF}' /proc/$PID/maps | sort -u > $SNAP/sos.txt

# 基础三件套
grep -E 'VmRSS|VmSize' /proc/$PID/status > $SNAP/rss
ls /proc/$PID/task | wc -l > $SNAP/threads
echo "snap done at $SNAP"
```

T0 跑一次,等 30-60 min(够看到 ≥ 100 MB 涨幅),T1 用同样命令再跑一次。下文以 `$SNAP_T0` / `$SNAP_T1` 指代两份目录。

---

## 2. Exp-A:per-arena 分布(最重要,优先做)

**目的**:增长是否真"均匀分布到所有 worker",还是集中在某几个 arena / 主线程。这条直接决定要不要保留"all-workers 稳态路径"这条约束。

### 抽取每个 arena 的 `<system current>`

```bash
awk -F'"' '
  /<heap nr=/        { arena = $2; in_heap = 1; sys = 0; next }
  /<\/heap>/         { if (in_heap) printf "%4d %12d\n", arena, sys; in_heap = 0; next }
  in_heap && /<system type="current"/ { sys = $4 }
' $SNAP/mi.xml | sort -k2 -n > $SNAP/arena_sizes.txt

echo "arena    size_bytes   size_MB"
awk '{printf "%4d  %12d  %8.1f\n", $1, $2, $2/1024/1024}' $SNAP/arena_sizes.txt
echo "---"
awk '{n++; sum+=$2; if($2>mx)mx=$2; if(mn==""||$2<mn)mn=$2}
     END{printf "arenas=%d  total=%.1fGB  avg=%.0fMB  min=%.0fMB  max=%.0fMB  max/avg=%.1fx\n",
         n, sum/1024/1024/1024, sum/n/1024/1024, mn/1024/1024, mx/1024/1024, mx/(sum/n)}' \
    $SNAP/arena_sizes.txt
```

### 判读

| `max/avg` 比 | 含义 | 对画像的影响 |
|---|---|---|
| **< 2×** | 真均匀,每 arena ~330 MB | 保留 "all-workers 稳态" 约束;Pattern E / Alt-8 升权 |
| **2× ~ 10×** | 有热点 worker | "All-workers" 约束**削弱**;某 1-2 个 worker 业务路径有特殊 leak |
| **> 10× 且 top 是 arena 0** | **主线程在涨**(arena 0 是 main arena) | 完全推翻 worker 画像 → **重看 init / main 上的 manager / singleton** |
| **> 10× 且 top 是 arena N (N>0)** | 单 thread arena 异常 | 找哪个 worker 用这个 arena;`gdb -ex 'info thread'` 关联 |

### T0 → T1 增量对照

```bash
join -j1 -o "1.1,1.2,2.2" \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | \
    awk '{printf "arena %4d: %8.1f -> %8.1f MB  (Δ %+7.1f MB)\n",
          $1, $2/1024/1024, $3/1024/1024, ($3-$2)/1024/1024}' | \
    sort -k7 -n
```

看 Δ 列:增长均匀分布,还是集中在某几个 arena。

---

## 3. Exp-B:三个大段是否在涨

**目的**:确认增长是只来自新增 64 MB subheap,还是也有大段在长大。

```bash
echo "=== T0 big segs ==="; cat $SNAP_T0/big_segs.txt
echo "=== T1 big segs ==="; cat $SNAP_T1/big_segs.txt
echo "=== diff(by address) ==="
diff $SNAP_T0/big_segs.txt $SNAP_T1/big_segs.txt

# 按地址匹配,跟踪每个段的 RSS 变化
join -j1 $SNAP_T0/big_segs.txt $SNAP_T1/big_segs.txt 2>/dev/null | \
    awk '{printf "addr=%-18s  virt: %s -> %s KB  rss: %s -> %s KB  (Δrss %+d KB)\n",
          $1, $2, $4, $3, $5, $5-$3}'
```

### 判读

| 现象 | 含义 |
|---|---|
| 3 段 RSS 完全稳定,只有 64 MB subheap 数在涨 | **"多小对象在容器里累积"画像更强** |
| 中段(2-5 亿字节)的 RSS 在涨 | **Alt-1 单大对象** / **Alt-2 自管理 pool** 可能性升高 — 找业务里"反复 append 一个大 vector/string"或"自定义 arena/pool" |
| reserve 段(virt 大 / RSS 极小)RSS 也涨了 | reserve 区在被 commit — **典型 pool allocator 正在分配新页**,Alt-2 几乎锁定 |
| T1 出现新的 > 64 MB 段 | 业务在 mmap 大块新对象,可能是协议 buffer / 大请求 |

---

## 4. Exp-C:in-use chunk 大小分布(可选,贵)

**目的**:看正在持有的对象**实际大小分布**(不是过去 freed 的 ~512 B 均值,那个不可靠)。

仅在 Exp-A/B/D/E 没能收窄画像、需要"对象实际多大"这条信息时做。

### 操作

```bash
# 板上(进程冻几十秒,~ 21 GB 文件)
ulimit -c unlimited
gcore -o /tmp/myapp $PID
scp /tmp/myapp.$PID dev:/data/
```

dev 机上跑 gdb-heap walker(让内部模型给你写脚本,框架如下):

```python
# heap_histo.py — 在 gdb 里 source 此文件
import gdb
from collections import Counter

ma = gdb.parse_and_eval("main_arena")
inuse_count = Counter()
inuse_bytes = Counter()

def bucket(sz):
    if sz < 64:       return "< 64 B"
    if sz < 256:      return "64-256 B"
    if sz < 1024:     return "256 B-1 KB"
    if sz < 4096:     return "1-4 KB"
    if sz < 65536:    return "4-64 KB"
    if sz < 1048576:  return "64 KB-1 MB"
    return "> 1 MB"

# 遍历所有 arena(main + thread arenas via .next 链),
# 对每个 arena 从 heap 基址走 chunk 链直到 top,
# 检查 PREV_INUSE bit 判断 in-use,落桶
# (具体实现让内部模型补,glibc 2.34 chunk layout 已稳定)
```

```bash
gdb -batch /path/to/binary /data/myapp.$PID -ex 'source heap_histo.py'
```

### 判读

| 直方图形态 | 含义 |
|---|---|
| 大量 64 B - 1 KB,合计 60%+ | **真"许多小对象"画像** → Pattern A/B/D 优先 |
| 几个 GB 级巨块 + 大量小块 | **Alt-1 单大对象**(大块 = 该对象主存) + 该对象内部 sub-allocation(小块) |
| 全部集中在一个 round number(64/128/256/512 B) | **Alt-2 pool allocator**,slab size 等于这个值 |
| 主要在 4-64 KB | 业务对象更胖(record / structured),不是 string/node 级 |
| 单个超大块 ≥ 1 GB | 高度可能 Alt-1,单 vector / 单 string |

---

## 5. Exp-D:线程 backtrace 分类

**目的**:区分 Alt-3 异步队列背压 vs 真稳态业务流量。

```bash
# 提取每个 Thread 的 #0 帧,统计栈顶函数
awk '
  /^Thread / { in_t = 1; next }
  in_t && /^#0/ {
    if (match($0, / in [^ (]+/)) {
      fn = substr($0, RSTART+4, RLENGTH-4)
    } else { fn = $NF }
    print fn; in_t = 0
  }
' $SNAP/threads.bt | sort | uniq -c | sort -rn

# 简化版:看关键等待原语出现次数
grep -oE '__GI___pthread_cond_wait|epoll_wait|pselect|nanosleep|__libc_(recv|send|read|write)|futex_wait|sem_wait' \
    $SNAP/threads.bt | sort | uniq -c | sort -rn
```

### 判读(59 线程为基准)

| 主要分布 | 含义 |
|---|---|
| ≥ 40 在 `pthread_cond_wait` / `futex_wait` / `sem_wait` | 大部分线程**空闲等任务**;若数据仍在涨 → **极可能 Alt-3 背压**(producer 跑得动,consumer 醒不来) |
| ≥ 30 在 `epoll_wait` / `read` | IO 等待,正常 server worker pool |
| 大部分在业务函数 | 业务在 CPU-bound 持续产生数据,真稳态 |
| 几乎所有都在同一个 cond / 同一把锁 | **可能死锁 / 一个慢消费者堵住所有 producer** |

### 跟 Exp-A 联动

- Exp-A 显示 arena 分布**均匀**,但 Exp-D 显示**大多数线程在等** → 矛盾。可能:等待线程也在**触发回调**(注册新订阅)→ **Alt-8 注册激增**;或等待线程持有**已分配未送达**对象 → Alt-3
- Exp-A 显示**集中在 arena 0**,Exp-D 显示**大量线程在 cond_wait** → **主线程在涨,worker 都闲着** → 完全推翻 worker 画像,改查初始化路径 / main 上的容器

---

## 6. Exp-E:dlopen 是否在继续加载

**目的**:排除 Alt-7(动态加载越来越多 .so)。

```bash
echo "=== T0 .so count ==="; wc -l $SNAP_T0/sos.txt
echo "=== T1 .so count ==="; wc -l $SNAP_T1/sos.txt

echo "=== T1 新增的 .so ==="
comm -13 $SNAP_T0/sos.txt $SNAP_T1/sos.txt

echo "=== T1 消失的 .so ==="
comm -23 $SNAP_T0/sos.txt $SNAP_T1/sos.txt
```

### 判读

| 现象 | 含义 |
|---|---|
| .so 数 T0 = T1,无新增无消失 | **排除 Alt-7** |
| 新增 .so 数 > 0(尤其反复同名) | 业务有 plugin / 动态加载,可能反复 dlopen — 检查有无对应 dlclose |
| 数量稳定但"消失 + 新增"对称 | 正常 plugin reload,但要看 dlclose 是否真释放(glibc 对 `RTLD_NODELETE` / 引用计数有限制) |

---

## 7. 跑完后的修订表

填这张表,然后再让内部模型扫源码:

| 维度 | 数据 | 修订后约束 |
|---|---|---|
| arena 分布 (Exp-A) | max/avg = ?× | 锁定单 arena / 主线程 / 均匀 worker 之一 |
| 大段 (Exp-B) | 三段 ΔRSS = ? | 锁定 multi-small-object / single-large-object / pool 之一 |
| in-use 分布 (Exp-C,可选) | 直方图主峰 = ? | 锁定累积对象的真实 size 范围 |
| 线程行为 (Exp-D) | 等待/工作/IO 比例 | 锁定背压 vs 真稳态产生 |
| dlopen (Exp-E) | .so 是否在涨 | 是/否 — 决定要不要查 Alt-7 |

**修订后画像 = 原 handoff §3 约束 ∩ 上面 5 条新增约束**。

修订后给审查方的 prompt 可能从"long-lived 容器小对象漏 erase"改成:
- "**主线程**(arena 0)上的 long-lived 容器,对象**平均 4-16 KB**,触发频率每秒几十次"
- 或:"**所有 worker 均匀贡献**,但栈显示大部分线程在等 — 找**消费速度跟不上 producer** 的队列"
- 或:"**单个**大对象在某段里持续 append,找业务里反复 `+=` / `push_back` 的位置"
- 或:"slab size = 256 B 的 pool allocator 在涨 — 找业务里的 `boost::pool` / 自定义 arena"

---

## 8. 决策树

```
Exp-A 跑完
 ├─ max/avg < 2×        → 画像保留;继续 Exp-B/D/E 验证
 ├─ max/avg 2-10×       → 画像收紧到"少数热 worker"
 ├─ arena 0 dominant    → 推翻 worker 画像,改查主线程
 └─ 某 thread arena 单飞 → 关联线程,查该 worker 业务路径

Exp-B 跑完
 ├─ 大段稳定            → 多小对象路线
 ├─ 中段 RSS 涨         → Alt-1 / Alt-2 升权,做 Exp-C
 └─ reserve 段被 commit → 几乎锁定 Alt-2 pool

Exp-D 跑完
 ├─ 大部分等待 + 数据涨  → Alt-3 背压 / Alt-8 注册
 ├─ 大部分在 IO/业务    → 真稳态产生
 └─ 同一把锁/cond 堆积  → 死锁式背压

Exp-E 跑完
 ├─ .so 数稳定          → 排除 Alt-7
 └─ .so 在涨            → 锁定 Alt-7,反复 dlopen
```

跑完上述,再决定:
- 画像不变 → 用原 handoff §3 给内部模型
- 画像变了 → 改 handoff §3,再扫
- 矛盾出现 → 回头检查 Phase 0 数据完整性

---

## 9. 配套文件

- 方法论 skill:`.claude/skills/cpp-memleak/SKILL.md`(本手册属于 Phase 2-3 之间的细化步骤)
- 完整诊断过程:`docs/cpp_aarch64_memleak_investigation.md`
- 源码审查交接:`docs/cpp_memleak_source_review_handoff.md`(其 §3 约束在本手册之后会被修订)
- 本文:`docs/cpp_memleak_constraint_experiments.md`
