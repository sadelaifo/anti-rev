# C++ aarch64 程序内存增长诊断 — 工作文档

> 工作类型:**进行中的诊断**(非结题报告)
> 跟踪分支:`xcc_memleak`
> 适用对象:跑在 aarch64 GPB 板上的 C++ 业务进程,默认 glibc ptmalloc,工具受限(无 bcc/heaptrack/valgrind)

---

## 1. 现象与背景

| 项 | 内容 |
|---|---|
| 平台 | Linux aarch64,GPB 板(嵌入式/服务器板) |
| 程序 | C++ 业务进程(长跑型,有源码) |
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

### 4.3 结果记录区(填回本文档)

| 项 | T0 | T1 | Δ |
|---|---|---|---|
| RSS | (待填) | | |
| VSZ | | | |
| 64 MB subheap 数 | 309 | | |
| `<system current>` | 20.17 GB | | |
| `<total fast>` | 73 KB | | |
| `<total rest>` | 469 MB | | |
| `<total mmap>` | 665 MB | | |
| 线程数 | 59 | | |

**判读结论**:(等 T1 后填)

---

## 5. 源码审查方向(有源码 → 必做)

Snapshot diff 给出**外部表象**(系统视角),源码审查给出**内部嫌疑**(代码视角),两边交叉验证最有效。

### 5.1 重点扫描的代码模式

```bash
# 在 C++ 业务源码根目录下跑(替换 <SRC> 为你的源码根):
SRC=<源码根>

# 5.1.1 裸 new(高危,看是不是配对了 delete / 接进 unique_ptr)
grep -rn '\bnew\b' --include='*.cpp' --include='*.cc' --include='*.h' $SRC \
    | grep -v '//\|/\*\|new_' \
    > /tmp/raw_new.txt
wc -l /tmp/raw_new.txt

# 5.1.2 全局/静态容器(unbounded 来源)
grep -rEn '^(static\s+)?std::(map|unordered_map|vector|list|deque|set|queue|multimap|multiset)<' \
    --include='*.cpp' --include='*.h' $SRC

# 5.1.3 单例 / 全局状态
grep -rEn 'singleton|getInstance|Instance\(\)|static\s+.*\s+&\s*\w+\(\)' \
    --include='*.cpp' --include='*.h' $SRC

# 5.1.4 容器的 push/insert 操作(看有没有对应 erase/clear/eviction)
grep -rEn 'emplace_back|push_back|insert\(|emplace\(' \
    --include='*.cpp' $SRC | wc -l

# 5.1.5 回调/observer 注册(看有没有 unregister/detach)
grep -rEn 'register|subscribe|addListener|on(Event|Connect|Message)' \
    --include='*.cpp' --include='*.h' $SRC | wc -l

# 5.1.6 shared_ptr 循环引用风险(this 被 capture 进 lambda / member 持有 shared_ptr)
grep -rEn '\[.*this.*\]|shared_from_this' --include='*.cpp' $SRC | head -50

# 5.1.7 大对象直接 new(大 buffer / 矩阵 / 大字符串)
grep -rEn 'new\s+(char|byte|int|float|double)\[' --include='*.cpp' $SRC

# 5.1.8 第三方库的常见 leak 来源
grep -rEn 'protobuf::Arena|libcurl|curl_multi|SSL_CTX_new|EVP_|av_malloc' \
    --include='*.cpp' --include='*.h' $SRC
```

### 5.2 业务侧自问 7 题

每题如果**回答不出"yes 且有上限"**,就是嫌疑点:

1. 进程里**最大的容器是哪个**?它有没有 size 上限?
2. **缓存**有没有 eviction(LRU、TTL、count-cap、bytes-cap)?
3. **日志 / metric / event 历史记录**有没有滚动/截断?
4. **session / 连接上下文**断开时是否真的释放(不是只标记 dead)?
5. **后台 thread / coroutine** 的局部状态是不是单调增长?(尤其 thread_local 容器)
6. **第三方库的全局**:protobuf Arena 是否 Reset?libcurl multi handle 是否 cleanup?SSL session cache 有没有限?
7. **shared_ptr 是否有循环引用**?(member 持有 shared_ptr<callback>,callback capture 了 shared_ptr<this>)

### 5.3 静态分析工具(本机或离线 dev 机)

```bash
# cppcheck(几乎所有发行版都有)
cppcheck --enable=all --inconclusive --suppress=missingIncludeSystem \
         -j4 --output-file=/tmp/cppcheck.log $SRC

# clang-tidy(更慢但更细)
clang-tidy -checks='cppcoreguidelines-*,bugprone-*,modernize-use-smart-ptr' \
           -p <build_dir> $SRC/*.cpp 2>&1 | tee /tmp/clang_tidy.log
```

关注的检查项:
- `cppcoreguidelines-owning-memory`(谁拥有 new 出来的对象)
- `bugprone-use-after-move`、`bugprone-unchecked-optional-access`
- `modernize-use-smart-ptr`(裸 new 提示)

### 5.4 嫌疑代码登记

把扫描和审查发现的可疑点登记在这里(由人工填写):

| 优先级 | 文件:行 | 模式 | 备注 | 状态 |
|---|---|---|---|---|
| (待填) | | | | |

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
