# 约束收窄实验手册 — 在源码审查之前/同时做

> ## 重要更新(2026-06-04):重启 = 诊断窗口
>
> 目标进程**在调查中被重启了**(可能由 OOM-kill、手动 kill、定期维护、压力测试 触发),RSS 从 21 GB 回落到 3 GB。
>
> **不要把重启当成数据损失** —— 这反而是抓 leak 起源**信噪比最高的时刻**。理由:
>
> - **21 GB 稳态** 下,新增 100 MB/h 的 leak 信号被 200× 的稳态历史数据淹没,集中度信号已被压缩成"既成事实"
> - **3 GB 起步** 时,从 3 → 6 → 10 → 15 GB 这段增长曲线**正在发生**,集中度**演化过程**可见,leak 起源更容易锁定
> - **线程名还干净**:fork / exec / pthread_setname 链还没覆盖初始 entry function 命名,Exp-F 的 arena→tid 映射更可读
> - **过去一轮(21 GB)的证据仍然成立**(arena max/avg = 45.9× 集中 + 大段稳定 + 3.88 GB/天),作为前一轮独立观察可与本轮做**复现验证**
>
> ### 立刻该做的事
>
> 1. **采 baseline snapshot**(§1 命令在新 PID 上跑一遍)
> 2. **立刻做 Exp-F**(§9)— 现在 arena→tid 映射比 21 GB 时容易,而且能在 leak 起源前就有早期 layout
> 3. **检查现在 max/avg 是不是已经 > 5×**(§2)—— 决定下一步等待 vs 立即追踪
> 4. **后续按 6 / 24 / 48 h 节奏多点采样**(详见 §11)
>
> 详细 playbook 见 **§11 重启诊断窗口**。
>
> ---

> **位置**:`cpp-memleak` skill 的 Phase 2-3 之间;handoff 文档的 §3 约束**收紧/可能修订**的依据。
> **触发场景**:Phase 0-1 已完成、已得出"long-lived 容器 + 小对象 + 漏清理"类初步画像,但**还没把源码交给审查方之前**,有必要再做一次廉价的多假设交叉验证,避免画像收得过紧导致内部审查走错方向。
> **执行条件**:板上有 `gdb`、`pmap`、`awk`、`grep` 即可。**全程不重启,不改业务代码**(§11 重启诊断窗口除外 —— 那是借重启发生的机会做额外采样,不是新增重启)。

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

**如果板上没有 `join`**(BusyBox / 精简 coreutils 常见),用 awk 两遍法替代:

```bash
awk 'NR==FNR{a[$1]=$2; next}
     {printf "arena %4d: %8.1f -> %8.1f MB  (Δ %+7.1f MB)\n",
             $1, a[$1]/1024/1024, $2/1024/1024, ($2-a[$1])/1024/1024}' \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | sort -k7 -n
```

如果连这都嫌麻烦,直接肉眼对照 `tail -5` 两份文件即可。

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
 ├─ max/avg > 10×       → 单线程集中,必须做 Exp-F 映射 tid
 ├─ arena 0 dominant    → 推翻 worker 画像,改查主线程(也走 Exp-F 确认)
 └─ 某 thread arena 单飞 → Exp-F 映射 tid,查该 worker 业务路径

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

Exp-F 跑完(仅当 Exp-A 触发集中)
 ├─ top arena = 0        → 主线程 leak,查 init + main 上长寿对象
 ├─ top arena = N,tid=X  → 线程 X leak,查它的 entry function 调用链
 └─ 找不到 thread_arena   → 走 gcore + dev 机 fallback
```

跑完上述,再决定:
- 画像不变 → 用原 handoff §3 给内部模型
- 画像变了 → 改 handoff §3,再扫
- 矛盾出现 → 回头检查 Phase 0 数据完整性

---

## 9. Exp-F:单 arena 集中 → 映射到具体线程

**触发条件**:Exp-A 显示 `max/avg > 10×`,或 top arena 持有占总 RSS ≥ 50%。结论:**不是 all-workers 均匀贡献**,而是**单线程独占**。下一步必须把那个 arena **映射到具体 tid**,才能进入定向源码审查。

> 本 case (2026-06-04) 实测 `max/avg = 45.9×`,正是这种集中场景。

### 步骤 1:列出所有 arena 的地址 + system_mem

ptmalloc 的 arena 链以 `main_arena` 为头,通过 `next` 指针串成环。

```bash
gdb -batch -p $PID \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' \
    -ex 'set $n = 0' \
    -ex 'while 1' \
    -ex '  printf "arena %3d  addr=%p  sysmem=%9lu KB  threads=%lu\n", \
              $n, $a, $a->system_mem/1024, $a->attached_threads' \
    -ex '  set $a = $a->next' \
    -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' \
    -ex '    loop_break' \
    -ex '  end' \
    -ex 'end' \
    -ex 'detach' 2>&1 | tail -80 > $SNAP/arena_addr.txt
sort -k4 -nr $SNAP/arena_addr.txt | head -10   # top 10 by sysmem
```

若 `main_arena` 找不到(glibc strip 过):

- 试 `ptmalloc_main_arena`
- 试 `&main_arena_storage`
- 终极 fallback:取 `gdb` 里 `info proc mappings` 中 `[heap]` 起始地址,glibc 的 main_arena 在 heap 起点的 sysconf 之内,可手算

### 步骤 2:列出每个线程当前所在 arena

glibc 用线程局部变量 `thread_arena` 标记本线程所在 arena:

```bash
gdb -batch -p $PID \
    -ex 'thread apply all printf "tid=%d arena=%p\n", $_thread, thread_arena' \
    -ex 'detach' 2>&1 | grep ^tid= | sort -k2 > $SNAP/tid_arena.txt
cat $SNAP/tid_arena.txt | head -20
```

变体(符号不同 glibc 版本不一样):
- 试 `_thread_arena`
- 试 `__libc_thread_arena`
- 若全部失败:用 `gdb` 在每个线程上 `print *(void**)(pthread_self() + offset)`,offset 需对 glibc 版本调试出来

### 步骤 3:匹配 top arena 地址 ↔ tid

把步骤 1 的 top arena 地址,跟步骤 2 里 tid 输出的 arena 列对照,确定**嫌疑 tid**。

```bash
TOP_ARENA=<填步骤 1 输出的 top arena 地址,如 0x7f1234567000>
grep $TOP_ARENA $SNAP/tid_arena.txt
```

### 步骤 4:回看该 tid 的 backtrace

回到 Exp-D 已抓的 `$SNAP/threads.bt`:

```bash
SUSPECT_TID=<填步骤 3 找到的 tid>
awk -v t="Thread $SUSPECT_TID" '
  $0 ~ "^"t" |\\(LWP "t"\\)" { in_t=1 }
  in_t { print }
  /^$/ { in_t=0 }
' $SNAP/threads.bt
```

栈顶函数 + 栈底(线程 entry 函数)就是嫌疑代码区间。

### 判读

| top arena 编号 | 嫌疑线程身份 | 下一步定向审查 |
|---|---|---|
| **0** (`main_arena`) | **主线程** | 查 `main()` 上的 Singleton / Manager / 主事件循环里的全局状态;init 阶段创建的长寿对象 |
| **N > 0** + 映射到 tid X | 线程 X | 该线程的 entry function(看 backtrace 底部);看它独占持有的容器、独占的 callback chain、它消费/生产的队列 |
| 找不到映射(`thread_arena` 全 0 或全相同) | gdb 符号不可用 | 用下面的 gcore 备选离线分析 |

### 备选:gcore 离线分析

板上 gcore + dev 机做相同的 arena 遍历:

```bash
# 板上
ulimit -c unlimited
gcore -o /tmp/m $PID
scp /tmp/m.$PID dev:/data/
```

dev 机:

```bash
gdb /path/to/binary /data/m.$PID -ex 'py
import gdb
ma = gdb.parse_and_eval("main_arena")
arena = ma.address
seen = []
while True:
    addr = int(arena)
    if addr in seen: break
    seen.append(addr)
    sm = int(arena.dereference()["system_mem"])
    at = int(arena.dereference()["attached_threads"])
    print(f"arena {len(seen)-1}: addr=0x{addr:x}  sysmem={sm/1024/1024:.1f}MB  threads={at}")
    arena = arena.dereference()["next"]
'
```

dev 机有完整符号,容易找到 top arena;然后回板上做步骤 2-3 映射 tid。

### 输出 → 修订 handoff §3

把 Exp-F 结果填到 `cpp_memleak_source_review_handoff.md` §3,例如:

> **修订后画像**:thread tid=X(entry function = `Foo::worker_loop`)持有 ~15 GB live 对象。其他 58 线程不参与。审查范围 = 该 tid 的调用栈所触及的代码,而非全代码库。

---

## 11. 重启诊断窗口 playbook

### 11.1 触发条件

进程在调查期间被重启,或可以借调度窗口主动安排一次重启。**两种情形都按本节做**。

### 11.2 为什么重启反而是机会

| 维度 | 长稳态 (21 GB) | 新进程 (3 GB) |
|---|---|---|
| arena 集中度信号 | 已经成形,是"既成事实" | **演化中**,可见 leak 起源从均匀到集中的过程 |
| 线程名 (`pthread_name`) | 可能已被覆盖 / 失语义 | 仍是初始 entry,可读 |
| `pmap` 段数 | 庞杂,几百个 64 MB 段 + 多个大段 | 段少且清晰,diff 显眼 |
| 多 baseline 可用 | 单点采样 | 可连续采 3-5 个时点,描出**完整增长曲线** |
| 复现验证 | 单轮观察 | 跟前一轮 21 GB 时的数据 **可对比、可证伪** |
| 对照实验 | 不能改 env(无重启窗口) | 可借此次重启加 `MALLOC_ARENA_MAX=2` / jemalloc 等做 A/B |

### 11.3 立刻做(< 30 min)

#### 11.3.1 baseline snapshot

```bash
PID=<新进程 PID>
T=$(date +%Y%m%d_%H%M)_baseline
SNAP=/tmp/mem_snap/$T
mkdir -p $SNAP

# §1 的完整采集
grep -E 'VmRSS|VmSize' /proc/$PID/status > $SNAP/rss
gdb -batch -p $PID \
    -ex "set \$f = (void *)fopen(\"$SNAP/mi.xml\", \"w\")" \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)' > /dev/null 2>&1
pmap -x $PID > $SNAP/pmap.full
awk '$2 > 65536 {print $1, $2, $3}' $SNAP/pmap.full | sort > $SNAP/big_segs.txt
gdb -batch -p $PID -ex 'set pagination off' \
    -ex 'thread apply all bt 8' -ex 'detach' > $SNAP/threads.bt 2>&1
awk '/\.so/{print $NF}' /proc/$PID/maps | sort -u > $SNAP/sos.txt
ls /proc/$PID/task | wc -l > $SNAP/threads
echo "baseline at RSS=$(grep VmRSS $SNAP/rss) saved to $SNAP"
```

#### 11.3.2 立刻做 Exp-F (arena→tid 映射 + 抓线程名)

```bash
# arena 链 + system_mem
gdb -batch -p $PID \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' -ex 'set $n = 0' \
    -ex 'while 1' \
    -ex '  printf "arena %3d  addr=%p  sysmem=%9lu KB  attached=%lu\n", \
              $n, $a, $a->system_mem/1024, $a->attached_threads' \
    -ex '  set $a = $a->next' -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' -ex '    loop_break' -ex '  end' \
    -ex 'end' -ex 'detach' 2>&1 | tee $SNAP/arena_addr.txt | tail -80

# tid → arena 映射 + 线程名(关键:这时候名字最干净)
gdb -batch -p $PID \
    -ex 'thread apply all printf "tid=%d arena=%p name=", $_thread, thread_arena' \
    -ex 'thread apply all printf "%s\n", $_thread_name' \
    -ex 'detach' 2>&1 | grep -E '^tid=' > $SNAP/tid_arena.txt
cat $SNAP/tid_arena.txt
```

#### 11.3.3 检查现在是否已经集中

```bash
awk -F'"' '
  /<heap nr=/ { a=$2; in_h=1; s=0; next }
  /<\/heap>/  { if (in_h) printf "%4d %12d\n", a, s; in_h=0; next }
  in_h && /<system type="current"/ { s=$4 }
' $SNAP/mi.xml | sort -k2 -n > $SNAP/arena_sizes.txt
tail -5 $SNAP/arena_sizes.txt | awk '{printf "TOP arena %4d : %.1f MB\n", $1, $2/1024/1024}'
```

判读:
- **现在 max/avg > 5×** → leak 重启后立刻集中,**当前 top arena 就是嫌疑** → 直接拿 tid 给审查方
- **现在 max/avg ≈ 1**(均匀) → 集中是时间累积出来的,等下次涨到 5-6 GB 再观察 — 这本身也是有用结论:某 1 个 tid 在某段业务下开始独跑

### 11.4 多时点采样表

按 3.88 GB/天 速率推算(rate 来自前一轮 §3.4):

| 时点 | 预期 RSS | 行动 |
|---|---|---|
| **T0** (现在) | 3 GB | baseline (§11.3.1) + Exp-F (§11.3.2) + 集中度 (§11.3.3) |
| **T1** (+6 h) | ~4 GB | 重跑 §11.3.1 + §11.3.3;对比 arena Δ |
| **T2** (+24 h) | ~7 GB | 同上;集中度应该已经明显 |
| **T3** (+48-72 h) | ~10-15 GB | 同上;跟前一轮 21 GB 时的 top arena **应当一致** —— 证实复现 |

T0 → T1 / T2 / T3 之间用 §2.3 的 `awk` 两遍法做 Δ 对比:

```bash
awk 'NR==FNR{a[$1]=$2; next}
     {printf "arena %4d: %7.1f -> %7.1f MB  (Δ %+6.1f MB)\n",
             $1, a[$1]/1024/1024, $2/1024/1024, ($2-a[$1])/1024/1024}' \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | sort -k7 -nr | head -10
```

**Δ 排序第一名 = 增长最快的 arena**。把它的 sysmem 涨幅跟总 ΔRSS 比:
- top arena Δ ≈ 总 ΔRSS → **单 arena leak 复现**,锁定 tid
- top arena Δ ≪ 总 ΔRSS → 多 arena 都在涨,跟前一轮不同 → **必须重新审视前一轮结论**

### 11.5 可选:借此次重启做对照实验

如果**还有一次重启窗口可用**(下次维护时段、灰度环境、镜像副本),用这个机会做对照实验。每个实验都需要**单独一次重启**:

| 实验 env | 验证什么 | 判读 |
|---|---|---|
| `MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=131072` | leak 是 ptmalloc 多 arena 分布问题还是用户代码层真累积 | 若 RSS 仍以原速率涨且 max/avg 仍 > 5× → **真 leak**(arena 数被强制压到 2,集中必然落 main 或唯一 thread arena);若涨势缓和 50%+ → 前一轮看到的高利用率有相当一部分其实是多 arena 的不归还 |
| `LD_PRELOAD=$JEMALLOC` | 换 allocator 是否改变 RSS 行为 | jemalloc 通常更激进归还内存。若涨势照旧 → 真 leak;若 RSS 平稳 → ptmalloc 特有问题 |
| `LD_PRELOAD=./malloc_track.so`(自编 wrapper)+ 业务跑 1 h + `kill -SIGUSR1` 触发 dump | 真实 leak stack trace | 拿到 stack → addr2line → 跟 handoff 嫌疑表对照 |

**不要一次重启同时改多个 env** —— 隔离变量,每次只动一项。

### 11.6 跟原 §2-§9 实验的复用关系

| 原章节 | 在重启窗口怎么复用 |
|---|---|
| §2 Exp-A (per-arena) | **多时点重跑** — 观察集中度的演化曲线 |
| §3 Exp-B (大段) | 多时点重跑 — 看大段什么时候出现/长大 |
| §4 Exp-C (in-use 直方图) | 若 §11.4 T2 / T3 时已锁定单 arena,可做一次 gcore 拿确凿对象大小分布 |
| §5 Exp-D (线程 bt) | T0 做一次(线程名干净);T2 再做一次(看同一 tid 行为变化) |
| §6 Exp-E (.so) | T0 / T3 各做一次比较,排除 Alt-7 |
| §9 Exp-F (arena→tid) | **T0 必做** —— 早期映射;以后每次重跑可对比"tid 是否还绑在同一 arena" |

### 11.7 失败模式

| 现象 | 含义 | 处理 |
|---|---|---|
| T0 时 max/avg ≈ 1,过 24 h 仍 ≈ 1 | leak **不集中**,跟前一轮 45.9× 矛盾 | 前一轮的集中是**进程多日老化的副产品**而非 leak 本质 — 回头看是不是其他场景触发(具体业务高峰、长时积压);改回 all-workers 画像 |
| T0 / T1 / T2 总 ΔRSS 远低于 162 MB/h | 触发 leak 的业务流量没回来 | 等业务流量恢复,或主动触发负载 |
| 重启后 RSS 一直涨到 30 GB+ 不被 OOM | 内存超额比上次还宽 | 跟内核 OOM 配置无关,leak 行为可继续观察 |
| 重启的进程**没复现 leak**(RSS 长期稳定 ≤ 5 GB) | 前一轮可能是**特定环境/数据/时段**触发,不是普遍稳态 leak | 重要负面结论 — 重看前一轮的触发条件,可能是某次特殊业务事件触发的"半永久累积" |

---

## 12. 配套文件

- 方法论 skill:`.claude/skills/cpp-memleak/SKILL.md`(本手册属于 Phase 2-3 之间的细化步骤)
- 完整诊断过程:`docs/cpp_aarch64_memleak_investigation.md`
- 源码审查交接:`docs/cpp_memleak_source_review_handoff.md`(其 §3 约束在本手册之后会被修订)
- 本文:`docs/cpp_memleak_constraint_experiments.md`
