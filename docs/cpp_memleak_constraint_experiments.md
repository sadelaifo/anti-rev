# 约束收窄实验手册 — 在源码审查之前/同时做

> **位置**:`cpp-memleak` skill 的 Phase 2-3 之间;handoff 文档的 §3 约束**收紧/可能修订**的依据。
> **执行条件**:板上有 `gdb`、`pmap`、`awk`、`grep` 即可。**全程不重启,不改业务代码**(Round 3 重启诊断窗口除外 —— 那是借重启发生的机会做额外采样,不是新增重启)。

---

## 文档结构说明

本文档**按更新轮次倒排** —— 最新加入的内容在前。每个 Round 标明:
- **触发原因**(为什么需要这一轮)
- **加入了什么**(新的实验/playbook/技巧)
- **同步改动**(其他文档跟着变了什么)

但**操作流程**上,新读者仍应**先读 Round 4 操作安全规则**,再读 Round 1 的"同步采集"(它是所有实验的基础),然后按当前 case 状态跳到对应 Round。

---

## 第一原则:不能把业务进程搞挂

**诊断的目的是观察,不是修改**。本文档所有命令都**默认运行在生产或类生产环境**,业务进程不能因为诊断动作出现:
- 崩溃 / 段错误
- 业务线程死锁(被 gdb 操作锁住的 mutex 没被释放)
- 长时间停顿(gcore 类除外,需明确选窗口)
- 内存被写入修改

所有 Round 的命令都必须通过 **Round 4 操作安全规则**(R4.1-R4.4)的审视后才能执行。

---

## 更新日志(倒序)

| Round | 日期 | 触发 | 加入了什么 | 同步改动 |
|---|---|---|---|---|
| **Round 4** | 2026-06-04 | 在执行 R3.4 Exp-F 时 gdb 卡住,意识到原命令没有迭代上限 / 超时保护,gdb 卡住后强杀风险大;另发现 R3.4 子步骤顺序(原 R3.4.2 中间穿插 R3.4.3 集中度,再跳回 R3.4.2 步 5)逻辑不连贯 → 整段重排为 R3.4.1 ~ R3.4.6 线性流 | 操作安全规则(L0-L3 风险分级、6 条纪律);卡住诊断阶梯;已有命令的安全版替换;R3.4 线性化 | 所有 Round 的 gdb 命令统一加 `timeout` 包裹 + `while $n < N` 迭代上限;`call malloc_info` 标 L2 风险并给出 L1 替代;R3.4 拆成 6 步(baseline / arena walk / 集中度 / tid→arena / 线程名 / 钻取) |
| **Round 3** | 2026-06-04 | 目标进程被重启,RSS 21 GB → 3 GB | 重启诊断窗口 playbook(多时点采样、对照实验、失败模式) | SKILL.md Phase 0 strategic note;工作文档 §3.6 |
| **Round 2** | 2026-06-04 | Exp-A 实测 max/avg = 45.9× + 大段稳定 → 推翻"all-workers"画像 | Exp-F (arena → tid 映射);决策树补 Exp-F 分支;Exp-A 增量对照加 awk fallback (板上无 `join`) | handoff §3 加修订 callout;SKILL.md Phase 4 加 per-arena concentration check |
| **Round 1** | 2026-06-03 | 怀疑初步"long-lived 容器小对象漏 erase"画像过窄,可能漏 Alt-1 单大对象、Alt-2 pool、Alt-3 背压、Alt-7 dlopen 等 | Exp-A~E 五件套(per-arena、大段、in-use 直方图、线程 bt、dlopen);修订表;决策树 | 创建本文档 |

---

# Round 4 (2026-06-04 #2) — 操作安全规则 + 卡死诊断

## R4.1 风险等级

每条命令的风险等级 **必须** 在文档里标注。L2 / L3 命令需要明确判断后才执行。

| 等级 | 含义 | 例子 | 是否会影响业务 |
|---|---|---|---|
| **L0 — 无风险** | 只读 `/proc/PID/*` 文件 | `grep VmRSS`,`pmap -x`,`ls /proc/PID/task`,`cat /proc/PID/maps` | 否 |
| **L1 — 低风险** | gdb attach + **只读取**(不 call、不 set) | `info threads`,`info proc`,struct field 读取(`p main_arena.system_mem`),`thread apply all bt`,arena 链遍历 | gdb attach 时进程被短暂 ptrace-stop(典型 100 ms-数秒);gdb 安全退出后恢复 |
| **L2 — 中风险** | gdb **call 业务进程内函数**,劫持某个线程跑代码 | `call (void) malloc_info(0, $f)`,`call (void) malloc_stats()`,任何 `call ...` | call 期间该线程被劫持执行;**强杀 gdb 可能让线程栈帧损坏 + arena 锁不释放 → 业务死锁** |
| **L3 — 高风险** | 改业务进程状态 / 写内存 / 长时间冻结 | `set var x = ...`,`gcore`(冻 3-300 秒不等) | 直接改业务,或长时间停服;**只在明确窗口期做** |

**规则**:本文档默认所有命令 ≤ L1。**L2 / L3 命令必须在标题里显式标注**,执行前确认 OK 才跑。

## R4.2 操作纪律(必读)

1. **绝不强杀 gdb**(没有 `kill -9`)。gdb 被 SIGKILL 时如果正在 call 业务函数,目标线程栈帧可能损坏,持有的 arena 锁也不会释放 → **其他线程后续 malloc 时会死锁**。
   - 卡住时:**先 Ctrl-C**(gdb 会清理 pending call)
   - 等 30 秒还不返回:`pkill -TERM -f "gdb.*-p $PID"`(默认 SIGTERM,gdb 能处理)
   - 仍不返回:**接受这个 gdb 卡着,不要再 kill**。gdb 不退出 ptrace 锁定就维持,业务在 ptrace 锁下不会因为多卡几分钟出问题。让它自然超时或后续运维介入。

2. **每个 gdb 命令都包 `timeout`**:
    ```bash
    timeout 60 gdb -batch -p $PID -ex '...' -ex 'detach'
    ```
    `timeout` 默认发 SIGTERM,gdb 能干净退出。**禁止用 `timeout -s KILL`**。

3. **每个 gdb while 循环加迭代上限**:`while $n < 200`,**禁止 `while 1`**。万一指针损坏,最多打印 N 行就退出,不会无限循环。

4. **能读 struct 就不 call 函数**。例:per-arena system_mem 可以直接读 `main_arena.next->system_mem`,不需要 call malloc_info()。

5. **每个 gdb 命令加 `--nx -iex 'set auto-load off'`**。原因:很多板上 gdb 编译时 `--disable-python`,而 glibc 的 pretty-printer 是 Python 脚本 (`/usr/share/gdb/auto-load/.../libc.so.6-gdb.py`),gdb attach 时强行加载会报 `Scripting in the python language is not supported`,严重时让 gdb 在跑到我们的命令之前就退出。`--nx` 跳过 `.gdbinit`,`set auto-load off` 屏蔽自动加载,二者结合保证只跑我们指定的 -ex / 命令文件。

6. **多行 printf 不要在 bash 单引号里用 `\` 跨行**。bash 把 `\<newline>` 留在字符串里,gdb 可能把第二行当成独立命令处理。**单行写完**,或用 `gdb -x cmdfile` 的命令文件方式。

7. **gcore (L3) 仅在低峰时段做**。3 GB 进程冻 ~30 秒,21 GB 进程冻 ~3-5 分钟。**必须**:
    - 跟业务方确认时间窗口
    - 落盘到本地非 mmap 路径(`/tmp` 安全;不要 NFS / 远程挂载)
    - dump 完立刻 detach

8. **绝不做**:
    - `set var x = ...`(写业务内存)
    - `call free(...)` / `call any_business_function(...)`(L2 + 高副作用)
    - `signal SIG*` / 主动给业务发信号
    - 同时跑多个 gdb attach 到同一 PID(ptrace 互斥,后到的卡死)

## R4.3 卡住诊断阶梯

任何 gdb 命令卡住 30 秒以上,**先 Ctrl-C 让 gdb 退**,再走下面阶梯排查根因。每一步独立跑,出问题打住。

### R4.3.1 gdb 能不能 attach(L1,2-3 秒返回)

```bash
timeout 15 gdb -batch -p $PID -ex 'info proc' -ex 'detach' 2>&1 | head -20
```

- **几秒返回 + process info** → attach 正常,继续 R4.3.2
- **超时 / 无返回** → ptrace 被锁住。检查:
    - 是否别的 gdb 还 attach 着:`ps aux | grep "gdb.*$PID"`
    - ptrace_scope 是否禁了:`cat /proc/sys/kernel/yama/ptrace_scope`(0 / 1 ok;2 / 3 受限)
    - 进程是否还活着:`kill -0 $PID && echo alive`

### R4.3.2 `main_arena` 符号能不能看到(L1,2 秒)

```bash
timeout 15 gdb -batch -p $PID -ex 'p &main_arena' -ex 'detach' 2>&1 | grep -v '^\[' | tail -5
```

- **看到 `$1 = (struct malloc_state *) 0x7fxxxxxxxxxx`** → 符号可见,继续 R4.3.3
- **`No symbol "main_arena"` / `Cannot access memory`** → glibc 被 strip。装 `libc6-dbg` (Debian/Ubuntu) / `glibc-debuginfo` (CentOS),或走 R2.7 gcore 离线方案
- **卡住** → gdb 自身有问题,看 dmesg / 重启 gdb

### R4.3.3 `info threads` 能不能跑(L1,10-30 秒,~59 线程)

```bash
timeout 60 gdb -batch -p $PID -ex 'set pagination off' -ex 'info threads' -ex 'detach' 2>&1 | wc -l
```

- 输出 ~60 行 → 正常,继续 R4.3.4
- **超时** → 线程数过多或部分线程在不响应的 syscall。**不再尝试 thread apply 全集**,改用 `info threads | head -10` 只看头部样本

### R4.3.4 简化的 arena 链遍历(L1,带迭代上限)

```bash
timeout 60 gdb -batch -p $PID \
    -ex 'set pagination off' \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' \
    -ex 'set $n = 0' \
    -ex 'while $n < 200' \
    -ex '  printf "arena %3d  addr=%p  sysmem=%9lu KB  threads=%lu\n", \
              $n, $a, $a->system_mem/1024, $a->attached_threads' \
    -ex '  set $a = $a->next' \
    -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' \
    -ex '    loop_break' \
    -ex '  end' \
    -ex 'end' \
    -ex 'detach' 2>&1 | tail -80
```

唯一改动相对原 R2.2 / R3.4.2:`while 1` → `while $n < 200`,**最多 200 行就 break**,加 `timeout 60`。

### R4.3.5 线程映射 — 不取 `$_thread_name`

老 gdb 没有 `$_thread_name`,如果原命令在这里卡,把它去掉:

```bash
timeout 90 gdb -batch -p $PID \
    -ex 'set pagination off' \
    -ex 'thread apply all printf "tid=%d arena=%p\n", $_thread, thread_arena' \
    -ex 'detach' 2>&1 | grep '^tid=' | head -100
```

线程名后面单独用 `/proc/$PID/task/*/comm` 读(L0,不需要 gdb):

```bash
for tid in $(ls /proc/$PID/task); do
    echo "tid=$tid name=$(cat /proc/$PID/task/$tid/comm)"
done > $SNAP/tid_names.txt
```

然后用 awk merge 这两份输出:

```bash
awk 'NR==FNR{name[$1]=$2; next}
     {match($0, /tid=([0-9]+)/, m); t=m[1]; print $0, "name="name["tid="t]}' \
    $SNAP/tid_names.txt $SNAP/tid_arena.txt
```

## R4.4 已有命令的安全版替换

下表对照 Round 1-3 各命令的风险等级,以及发现问题后需替换的版本。

| 原章节 | 命令 | 风险 | 安全替换 |
|---|---|---|---|
| R1.1 `call malloc_info` | gdb call,L2 | gdb 卡住 / 强杀 → 业务 arena 锁可能死锁 | **优先**走 R4.3.4 的 struct walk 拿 per-arena system_mem;**只有**需要完整 fastbin/rest histogram 才用 malloc_info,且预先确认 `timeout 60` 够 |
| R2.2 arena 链遍历 | `while 1` | gdb,L1 但循环无上限 | 改为 `while $n < 200` + `timeout 60`(R4.3.4 的版本) |
| R3.4.2 arena 链 walk / R3.4.4 tid→arena | 同 R2.2 + 取 `$_thread_name` | gdb,L1 但循环无上限 + 老 gdb 可能挂在 `$_thread_name` | 同 R4.3.4 / R4.3.5;线程名走 `/proc/PID/task/*/comm`(L0,R3.4.5) |
| 所有 `gdb -batch -p $PID ...` | gdb attach | L1 | 全部包 `timeout 60` |
| R2.7 gcore | gcore | L3 (冻 30 s ~ 5 min) | 仅在窗口期做;3 GB 进程当前可接受,21 GB 进程必须协调 |
| `pkill -f "gdb..."` | gdb 清理 | 默认 SIGTERM,L0 | 保持默认信号,**禁止** `-9` / `-KILL` |

---

# Round 3 (2026-06-04) — 重启诊断窗口 playbook

## R3.1 重要提示:重启 = 诊断窗口

目标进程**在调查中被重启了**(可能由 OOM-kill、手动 kill、定期维护、压力测试 触发),RSS 从 21 GB 回落到 3 GB。

**不要把重启当成数据损失** —— 这反而是抓 leak 起源**信噪比最高的时刻**。理由:

- **21 GB 稳态** 下,新增 100 MB/h 的 leak 信号被 200× 的稳态历史数据淹没,集中度信号已被压缩成"既成事实"
- **3 GB 起步** 时,从 3 → 6 → 10 → 15 GB 这段增长曲线**正在发生**,集中度**演化过程**可见,leak 起源更容易锁定
- **线程名还干净**:fork / exec / pthread_setname 链还没覆盖初始 entry function 命名,Exp-F 的 arena→tid 映射更可读
- **过去一轮(21 GB)的证据仍然成立**(arena max/avg = 45.9× 集中 + 大段稳定 + 3.88 GB/天),作为前一轮独立观察可与本轮做**复现验证**

### 立刻该做的事

1. **采 baseline snapshot**(用 Round 1 同步采集命令在新 PID 上跑一遍)
2. **立刻做 Exp-F**(Round 2 章节)— 现在 arena→tid 映射比 21 GB 时容易,而且能在 leak 起源前就有早期 layout
3. **检查现在 max/avg 是不是已经 > 5×**(Round 1 — Exp-A)—— 决定下一步等待 vs 立即追踪
4. **后续按 6 / 24 / 48 h 节奏多点采样**(详见 R3.4)

## R3.2 触发条件

进程在调查期间被重启,或可以借调度窗口主动安排一次重启。**两种情形都按本节做**。

## R3.3 为什么重启反而是机会

| 维度 | 长稳态 (21 GB) | 新进程 (3 GB) |
|---|---|---|
| arena 集中度信号 | 已经成形,是"既成事实" | **演化中**,可见 leak 起源从均匀到集中的过程 |
| 线程名 (`pthread_name`) | 可能已被覆盖 / 失语义 | 仍是初始 entry,可读 |
| `pmap` 段数 | 庞杂,几百个 64 MB 段 + 多个大段 | 段少且清晰,diff 显眼 |
| 多 baseline 可用 | 单点采样 | 可连续采 3-5 个时点,描出**完整增长曲线** |
| 复现验证 | 单轮观察 | 跟前一轮 21 GB 时的数据 **可对比、可证伪** |
| 对照实验 | 不能改 env(无重启窗口) | 可借此次重启加 `MALLOC_ARENA_MAX=2` / jemalloc 等做 A/B |

## R3.4 立刻做(< 30 min)

操作顺序线性,**从上往下跑**:

| 步 | 干什么 | 输出文件 | 风险 |
|---|---|---|---|
| R3.4.1 | baseline snapshot (proc 读 + 全线程 bt) | `rss / pmap.full / big_segs.txt / sos.txt / threads / threads.bt` (+ 可选 `mi.xml`) | L0 + L1 (+ L2 可选) |
| R3.4.2 | arena 链 walk (`main_arena.next`) | `arena_addr.txt` | L1 |
| R3.4.3 | 算 max/avg + 找 top arena 编号 | (stdout) | L0 |
| R3.4.4 | tid → arena 映射 (`thread_arena`) | `tid_arena.txt` | L1 |
| R3.4.5 | 线程名 (走 `/proc/PID/task/*/comm`) | `tid_names.txt` | L0 |
| R3.4.6 | 钻取嫌疑 tid + backtrace (4 块数据) | (stdout,贴给工作文档 §3.6) | L0 |

### R3.4.1 baseline snapshot

> **风险**:L0(/proc 读)+ L1(gdb 只读 thread bt)+ **L2 可选(call malloc_info)**。malloc_info 卡住可跳过,主要数据靠 R3.4.2 struct walk。

```bash
PID=12345          # ← 填新进程 PID。不要用 <...> 占位,bash 把它当重定向
T=$(date +%Y%m%d_%H%M)_baseline
SNAP=/tmp/mem_snap/$T
mkdir -p $SNAP

# L0: /proc 只读
grep -E 'VmRSS|VmSize' /proc/$PID/status > $SNAP/rss
pmap -x $PID > $SNAP/pmap.full
awk '$2 > 65536 {print $1, $2, $3}' $SNAP/pmap.full | sort > $SNAP/big_segs.txt
awk '/\.so/{print $NF}' /proc/$PID/maps | sort -u > $SNAP/sos.txt
ls /proc/$PID/task | wc -l > $SNAP/threads

# L1: gdb 只读 — 线程 backtrace
timeout 90 gdb -batch -p $PID -ex 'set pagination off' \
    -ex 'thread apply all bt 8' -ex 'detach' > $SNAP/threads.bt 2>&1

# L2 可选: malloc_info(卡住 Ctrl-C,不要 -9)
timeout 30 gdb -batch -p $PID \
    -ex "set \$f = (void *)fopen(\"$SNAP/mi.xml\", \"w\")" \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)' \
    -ex 'detach' > /dev/null 2>&1 || echo "malloc_info skipped (L2 timeout)"

echo "baseline at RSS=$(grep VmRSS $SNAP/rss) saved to $SNAP"
```

### R3.4.2 arena 链 walk(L1)

> **常见陷阱**:板上 gdb 若编译时 `--disable-python`,attach 时 glibc pretty-printer 尝试加载 Python 会让 gdb 在跑到我们的 `while` 之前就报错退出。**永远加 `--nx -iex 'set auto-load off'`** 屏蔽掉。同样,printf 用**单行**,不要在 bash 单引号里用 `\` 跨行(老 gdb 会把第二行当独立命令)。

```bash
timeout 60 gdb -batch --nx \
    -iex 'set auto-load off' \
    -p $PID \
    -ex 'set pagination off' \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' \
    -ex 'set $n = 0' \
    -ex 'while $n < 200' \
    -ex '  printf "arena %3d  addr=%p  sysmem=%9lu KB  attached=%lu\n", $n, $a, $a->system_mem/1024, $a->attached_threads' \
    -ex '  set $a = $a->next' \
    -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' \
    -ex '    loop_break' \
    -ex '  end' \
    -ex 'end' \
    -ex 'detach' 2>&1 | tee $SNAP/arena_addr.txt | tail -80
```

输出 N 行(N = arena 数,典型 1-64)。如果卡 / 没输出 / 报符号错,走 **R4.3 卡死诊断阶梯**。

**如果仍报 "Scripting in the python language is not supported"** —— 用命令文件版本(完全绕开 `-ex` 多行处理):

```bash
cat > /tmp/gdb-arena.cmd <<'EOF'
set pagination off
set $ma = (struct malloc_state *)&main_arena
set $a = $ma
set $n = 0
while $n < 200
  printf "arena %3d  addr=%p  sysmem=%9lu KB  attached=%lu\n", $n, $a, $a->system_mem/1024, $a->attached_threads
  set $a = $a->next
  set $n = $n + 1
  if $a == $ma
    loop_break
  end
end
detach
EOF

timeout 60 gdb -batch --nx -iex 'set auto-load off' -p $PID -x /tmp/gdb-arena.cmd 2>&1 | \
    tee $SNAP/arena_addr.txt | tail -80
```

### R3.4.3 算 max/avg + 找 top arena(L0,纯 awk)

```bash
awk '/^arena / {
    n++; s = $6; sum += s;
    if (s > mx) { mx = s; mxn = $2; mxaddr = $4 }
    if (mn == "" || s < mn) mn = s
}
END {
    printf "arenas=%d  total=%.1f MB  avg=%.1f MB  max/avg=%.2fx  top=arena %s addr=%s (%.1f MB)\n",
        n, sum/1024, sum/n/1024, mx/(sum/n), mxn, mxaddr, mx/1024
}' $SNAP/arena_addr.txt

# top 5
echo "--- top 5 by sysmem ---"
sort -k6 -n $SNAP/arena_addr.txt | tail -5
```

判读:

- **max/avg > 5×** → 集中,当前 top arena 是嫌疑 → 继续 R3.4.4 找 tid
- **max/avg ≈ 1**(均匀) → 重启后还没出现集中,等 T1 (+6h) 再跑 R3.4.2 + R3.4.3
- **top 是 arena 0(main)** → 主线程在涨;继续 R3.4.4-6,但嫌疑代码区是 main 上的 manager / singleton
- **top 是 arena N > 0** → 某 worker 在涨;R3.4.4 找出 tid,R3.4.5/6 给它身份

### R3.4.4 tid → arena 映射(L1,**不用** `$_thread_name`)

```bash
timeout 90 gdb -batch --nx \
    -iex 'set auto-load off' \
    -p $PID \
    -ex 'set pagination off' \
    -ex 'thread apply all printf "tid=%d arena=%p\n", $_thread, thread_arena' \
    -ex 'detach' 2>&1 | grep '^tid=' > $SNAP/tid_arena.txt
echo "got $(wc -l < $SNAP/tid_arena.txt) tids"
head -5 $SNAP/tid_arena.txt
```

如果卡:看 **R4.3.5**(线程名分离方案)。如果报 Python 错:加 `--nx -iex 'set auto-load off'`(本命令已带)。

### R3.4.5 线程名(L0,走 `/proc`)

```bash
for tid in $(ls /proc/$PID/task); do
    echo "tid=$tid name=$(cat /proc/$PID/task/$tid/comm 2>/dev/null)"
done > $SNAP/tid_names.txt
head -5 $SNAP/tid_names.txt
```

### R3.4.6 钻取嫌疑 tid + backtrace(L0,合并所有上面)

用 R3.4.3 给出的 top arena 编号(本 case T0 = arena 55)钻进去:

```bash
TOP_ARENA_NUM=55       # ← 填 R3.4.3 输出的编号。不要写 <...>,bash 把它当重定向 → 变量会变空

# 1. top arena 的地址
echo "=== top arena $TOP_ARENA_NUM ==="
awk -v n=$TOP_ARENA_NUM '$2 == n {print}' $SNAP/arena_addr.txt
ARENA_ADDR=$(awk -v n=$TOP_ARENA_NUM '$2 == n {print $4}' $SNAP/arena_addr.txt)
echo "top arena addr = $ARENA_ADDR"

# 2. 该 arena 对应的 tid(可能 1 个或多个)
echo "=== tid 绑到此 arena ==="
grep "$ARENA_ADDR" $SNAP/tid_arena.txt

# 3. 嫌疑 tid 的线程名
SUSPECT_TID=$(grep "$ARENA_ADDR" $SNAP/tid_arena.txt | head -1 | grep -oE 'tid=[0-9]+' | head -1 | cut -d= -f2)
echo "suspect tid = $SUSPECT_TID"
echo "=== thread name ==="
grep "^tid=$SUSPECT_TID " $SNAP/tid_names.txt

# 4. 嫌疑 tid 的 backtrace
echo "=== suspect tid backtrace ==="
awk -v t="$SUSPECT_TID" '
    /^Thread / { in_t = (index($0, "(LWP "t")") > 0) }
    in_t { print }
    /^$/ && in_t { exit }
' $SNAP/threads.bt
```

输出的四块(arena 地址 / tid / name / backtrace)就是 handoff §3 从"某 worker 持有大量小对象"细化到 **"thread tid=X (name=Y, entry=Z) 持有 N% heap"** 的全部素材。直接贴给工作文档 §3.6 / handoff §3。

## R3.5 多时点采样表

按 3.88 GB/天 速率推算(rate 来自前一轮 工作文档 §3.4):

| 时点 | 预期 RSS | 行动 |
|---|---|---|
| **T0** (现在) | 3 GB | 全套 R3.4.1 → R3.4.6 跑完(含 tid 锁定) |
| **T1** (+6 h) | ~4 GB | R3.4.1 + R3.4.2 + R3.4.3(看集中度演化);若 top arena 跟 T0 一致,不需要重做 R3.4.4-6 |
| **T2** (+24 h) | ~7 GB | 同上;集中度应该已经明显 |
| **T3** (+48-72 h) | ~10-15 GB | 同上;跟前一轮 21 GB 时的 top arena **应当一致** —— 证实复现 |

T0 → T1 / T2 / T3 之间用 **Round 1 — Exp-A 章节末的 awk 两遍法**做 Δ 对比:

```bash
awk 'NR==FNR{a[$1]=$2; next}
     {printf "arena %4d: %7.1f -> %7.1f MB  (Δ %+6.1f MB)\n",
             $1, a[$1]/1024/1024, $2/1024/1024, ($2-a[$1])/1024/1024}' \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | sort -k7 -nr | head -10
```

**Δ 排序第一名 = 增长最快的 arena**。把它的 sysmem 涨幅跟总 ΔRSS 比:

- top arena Δ ≈ 总 ΔRSS → **单 arena leak 复现**,锁定 tid
- top arena Δ ≪ 总 ΔRSS → 多 arena 都在涨,跟前一轮不同 → **必须重新审视前一轮结论**

## R3.6 可选:借此次重启做对照实验

如果**还有一次重启窗口可用**(下次维护时段、灰度环境、镜像副本),用这个机会做对照实验。每个实验都需要**单独一次重启**:

| 实验 env | 验证什么 | 判读 |
|---|---|---|
| `MALLOC_ARENA_MAX=2 MALLOC_TRIM_THRESHOLD_=131072` | leak 是 ptmalloc 多 arena 分布问题还是用户代码层真累积 | 若 RSS 仍以原速率涨且 max/avg 仍 > 5× → **真 leak**(arena 数被强制压到 2,集中必然落 main 或唯一 thread arena);若涨势缓和 50%+ → 前一轮看到的高利用率有相当一部分其实是多 arena 的不归还 |
| `LD_PRELOAD=$JEMALLOC` | 换 allocator 是否改变 RSS 行为 | jemalloc 通常更激进归还内存。若涨势照旧 → 真 leak;若 RSS 平稳 → ptmalloc 特有问题 |
| `LD_PRELOAD=./malloc_track.so`(自编 wrapper)+ 业务跑 1 h + `kill -SIGUSR1` 触发 dump | 真实 leak stack trace | 拿到 stack → addr2line → 跟 handoff 嫌疑表对照 |

**不要一次重启同时改多个 env** —— 隔离变量,每次只动一项。

## R3.7 跟 Round 1 / Round 2 实验的复用关系

| 原章节 | 在重启窗口怎么复用 |
|---|---|
| Round 1 — Exp-A (per-arena) | **多时点重跑** — 观察集中度的演化曲线 |
| Round 1 — Exp-B (大段) | 多时点重跑 — 看大段什么时候出现/长大 |
| Round 1 — Exp-C (in-use 直方图) | 若 R3.5 T2 / T3 时已锁定单 arena,可做一次 gcore 拿确凿对象大小分布 |
| Round 1 — Exp-D (线程 bt) | T0 做一次(线程名干净);T2 再做一次(看同一 tid 行为变化) |
| Round 1 — Exp-E (.so) | T0 / T3 各做一次比较,排除 Alt-7 |
| Round 2 — Exp-F (arena→tid) | **T0 必做** —— 早期映射;以后每次重跑可对比"tid 是否还绑在同一 arena" |

## R3.8 失败模式

| 现象 | 含义 | 处理 |
|---|---|---|
| T0 时 max/avg ≈ 1,过 24 h 仍 ≈ 1 | leak **不集中**,跟前一轮 45.9× 矛盾 | 前一轮的集中是**进程多日老化的副产品**而非 leak 本质 — 回头看是不是其他场景触发(具体业务高峰、长时积压);改回 all-workers 画像 |
| T0 / T1 / T2 总 ΔRSS 远低于 162 MB/h | 触发 leak 的业务流量没回来 | 等业务流量恢复,或主动触发负载 |
| 重启后 RSS 一直涨到 30 GB+ 不被 OOM | 内存超额比上次还宽 | 跟内核 OOM 配置无关,leak 行为可继续观察 |
| 重启的进程**没复现 leak**(RSS 长期稳定 ≤ 5 GB) | 前一轮可能是**特定环境/数据/时段**触发,不是普遍稳态 leak | 重要负面结论 — 重看前一轮的触发条件,可能是某次特殊业务事件触发的"半永久累积" |

---

# Round 2 (2026-06-04) — Exp-F:单 arena 集中 → 映射到具体线程

## R2.1 触发条件

Round 1 — Exp-A 显示 `max/avg > 10×`,或 top arena 持有占总 RSS ≥ 50%。结论:**不是 all-workers 均匀贡献**,而是**单线程独占**。下一步必须把那个 arena **映射到具体 tid**,才能进入定向源码审查。

> 本 case (2026-06-04) 前一轮实测 `max/avg = 45.9×`,正是这种集中场景。

## R2.2 步骤 1:列出所有 arena 的地址 + system_mem

> **风险**:L1。已遵循 Round 4 R4.2:`timeout` 包裹 + `while $n < 200` 迭代上限。

ptmalloc 的 arena 链以 `main_arena` 为头,通过 `next` 指针串成环。

```bash
timeout 60 gdb -batch -p $PID \
    -ex 'set pagination off' \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' \
    -ex 'set $n = 0' \
    -ex 'while $n < 200' \
    -ex '  printf "arena %3d  addr=%p  sysmem=%9lu KB  threads=%lu\n", \
              $n, $a, $a->system_mem/1024, $a->attached_threads' \
    -ex '  set $a = $a->next' \
    -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' \
    -ex '    loop_break' \
    -ex '  end' \
    -ex 'end' \
    -ex 'detach' 2>&1 | tee $SNAP/arena_addr.txt | tail -80
sort -k6 -nr $SNAP/arena_addr.txt | head -10   # top 10 by sysmem
```

若 `main_arena` 找不到(glibc strip 过):

- 试 `ptmalloc_main_arena`
- 试 `&main_arena_storage`
- 终极 fallback:取 `gdb` 里 `info proc mappings` 中 `[heap]` 起始地址,glibc 的 main_arena 在 heap 起点的 sysconf 之内,可手算

## R2.3 步骤 2:列出每个线程当前所在 arena

> **风险**:L1。

glibc 用线程局部变量 `thread_arena` 标记本线程所在 arena:

```bash
timeout 90 gdb -batch -p $PID \
    -ex 'set pagination off' \
    -ex 'thread apply all printf "tid=%d arena=%p\n", $_thread, thread_arena' \
    -ex 'detach' 2>&1 | grep ^tid= | sort -k2 > $SNAP/tid_arena.txt
cat $SNAP/tid_arena.txt | head -20
```

变体(符号不同 glibc 版本不一样):

- 试 `_thread_arena`
- 试 `__libc_thread_arena`
- 若全部失败:用 `gdb` 在每个线程上 `print *(void**)(pthread_self() + offset)`,offset 需对 glibc 版本调试出来

## R2.4 步骤 3:匹配 top arena 地址 ↔ tid

把步骤 1 的 top arena 地址,跟步骤 2 里 tid 输出的 arena 列对照,确定**嫌疑 tid**。

```bash
TOP_ARENA=0x7f1234567000   # ← 填步骤 1 输出的 top arena 地址。不要写 <...>,bash 把它当重定向
grep $TOP_ARENA $SNAP/tid_arena.txt
```

## R2.5 步骤 4:回看该 tid 的 backtrace

回到 Round 1 — Exp-D 已抓的 `$SNAP/threads.bt`:

```bash
SUSPECT_TID=12345   # ← 填步骤 3 找到的 tid。不要写 <...>,bash 把它当重定向
awk -v t="Thread $SUSPECT_TID" '
  $0 ~ "^"t" |\\(LWP "t"\\)" { in_t=1 }
  in_t { print }
  /^$/ { in_t=0 }
' $SNAP/threads.bt
```

栈顶函数 + 栈底(线程 entry 函数)就是嫌疑代码区间。

## R2.6 判读

| top arena 编号 | 嫌疑线程身份 | 下一步定向审查 |
|---|---|---|
| **0** (`main_arena`) | **主线程** | 查 `main()` 上的 Singleton / Manager / 主事件循环里的全局状态;init 阶段创建的长寿对象 |
| **N > 0** + 映射到 tid X | 线程 X | 该线程的 entry function(看 backtrace 底部);看它独占持有的容器、独占的 callback chain、它消费/生产的队列 |
| 找不到映射(`thread_arena` 全 0 或全相同) | gdb 符号不可用 | 用下面的 gcore 备选离线分析 |

## R2.7 备选:gcore 离线分析

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

## R2.8 输出 → 修订 handoff §3

把 Exp-F 结果填到 `cpp_memleak_source_review_handoff.md` §3,例如:

> **修订后画像**:thread tid=X(entry function = `Foo::worker_loop`)持有 ~15 GB live 对象。其他 58 线程不参与。审查范围 = 该 tid 的调用栈所触及的代码,而非全代码库。

---

# Round 1 (2026-06-03) — 基础实验套件

## R1.0 为什么要做这个手册

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

## R1.1 同步采集 T0 / T1 snapshot

> **风险**:L0(/proc 读)+ L1(gdb 只读)+ **L2(call malloc_info)**。L2 那条带 `timeout` 保护,卡住可跳过;per-arena 用 R4.3.4 struct walk 替代不丢主要信息。

```bash
PID=12345          # ← 填进程 PID。不要用 <...>,bash 把它当重定向
T=$(date +%Y%m%d_%H%M)              # T0 / T1 各跑一次
SNAP=/tmp/mem_snap/$T
mkdir -p $SNAP

# L0: /proc 只读
grep -E 'VmRSS|VmSize' /proc/$PID/status > $SNAP/rss
pmap -x $PID > $SNAP/pmap.full
awk '$2 > 65536 {print $1, $2, $3}' $SNAP/pmap.full | sort > $SNAP/big_segs.txt
awk '/\.so/{print $NF}' /proc/$PID/maps | sort -u > $SNAP/sos.txt
ls /proc/$PID/task | wc -l > $SNAP/threads

# L1: gdb 只读 — 线程 backtrace
timeout 90 gdb -batch -p $PID -ex 'set pagination off' \
    -ex 'thread apply all bt 8' -ex 'detach' > $SNAP/threads.bt 2>&1

# L2: malloc_info(call 业务函数,优先级最低,卡住可跳过)
# 若不放心 L2,直接注释这段,改用下面 struct walk
timeout 30 gdb -batch -p $PID \
    -ex "set \$f = (void *)fopen(\"$SNAP/mi.xml\", \"w\")" \
    -ex 'call (void) malloc_info(0, $f)' \
    -ex 'call (int) fflush($f)' \
    -ex 'call (int) fclose($f)' \
    -ex 'detach' > /dev/null 2>&1 || echo "malloc_info skipped (L2 timeout)"

# L1 替代(无论 L2 是否跑了都建议同时收集 — 校验用)
timeout 60 gdb -batch -p $PID -ex 'set pagination off' \
    -ex 'set $ma = (struct malloc_state *)&main_arena' \
    -ex 'set $a = $ma' -ex 'set $n = 0' \
    -ex 'while $n < 200' \
    -ex '  printf "arena %3d sysmem=%lu\n", $n, $a->system_mem' \
    -ex '  set $a = $a->next' -ex '  set $n = $n + 1' \
    -ex '  if $a == $ma' -ex '    loop_break' -ex '  end' \
    -ex 'end' -ex 'detach' 2>&1 | grep '^arena ' > $SNAP/arena_sysmem.txt

echo "snap done at $SNAP"
```

T0 跑一次,等 30-60 min(够看到 ≥ 100 MB 涨幅),T1 用同样命令再跑一次。下文以 `$SNAP_T0` / `$SNAP_T1` 指代两份目录。

## R1.2 Exp-A:per-arena 分布(最重要,优先做)

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
| **> 10× 且 top 是 arena 0** | **主线程在涨**(arena 0 是 main arena) | 完全推翻 worker 画像 → **重看 init / main 上的 manager / singleton**;**必须**跳 Round 2 做 Exp-F |
| **> 10× 且 top 是 arena N (N>0)** | 单 thread arena 异常 | 找哪个 worker 用这个 arena;**必须**跳 Round 2 做 Exp-F 映射 |

### T0 → T1 增量对照

```bash
join -j1 -o "1.1,1.2,2.2" \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | \
    awk '{printf "arena %4d: %8.1f -> %8.1f MB  (Δ %+7.1f MB)\n",
          $1, $2/1024/1024, $3/1024/1024, ($3-$2)/1024/1024}' | \
    sort -k7 -n
```

**如果板上没有 `join`**(BusyBox / 精简 coreutils 常见,Round 2 实测板上无 `join`),用 awk 两遍法替代:

```bash
awk 'NR==FNR{a[$1]=$2; next}
     {printf "arena %4d: %8.1f -> %8.1f MB  (Δ %+7.1f MB)\n",
             $1, a[$1]/1024/1024, $2/1024/1024, ($2-a[$1])/1024/1024}' \
    $SNAP_T0/arena_sizes.txt $SNAP_T1/arena_sizes.txt | sort -k7 -n
```

如果连这都嫌麻烦,直接肉眼对照 `tail -5` 两份文件即可。

看 Δ 列:增长均匀分布,还是集中在某几个 arena。

## R1.3 Exp-B:三个大段是否在涨

**目的**:确认增长是只来自新增 64 MB subheap,还是也有大段在长大。

```bash
echo "=== T0 big segs ==="; cat $SNAP_T0/big_segs.txt
echo "=== T1 big segs ==="; cat $SNAP_T1/big_segs.txt
echo "=== diff(by address) ==="
diff $SNAP_T0/big_segs.txt $SNAP_T1/big_segs.txt

# 按地址匹配,跟踪每个段的 RSS 变化(同样若无 join 改 awk 两遍法)
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

## R1.4 Exp-C:in-use chunk 大小分布(可选,贵)

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

## R1.5 Exp-D:线程 backtrace 分类

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

### 判读(以 59 线程为基准)

| 主要分布 | 含义 |
|---|---|
| ≥ 40 在 `pthread_cond_wait` / `futex_wait` / `sem_wait` | 大部分线程**空闲等任务**;若数据仍在涨 → **极可能 Alt-3 背压**(producer 跑得动,consumer 醒不来) |
| ≥ 30 在 `epoll_wait` / `read` | IO 等待,正常 server worker pool |
| 大部分在业务函数 | 业务在 CPU-bound 持续产生数据,真稳态 |
| 几乎所有都在同一个 cond / 同一把锁 | **可能死锁 / 一个慢消费者堵住所有 producer** |

### 跟 Exp-A 联动

- Exp-A 显示 arena 分布**均匀**,但 Exp-D 显示**大多数线程在等** → 矛盾。可能:等待线程也在**触发回调**(注册新订阅)→ **Alt-8 注册激增**;或等待线程持有**已分配未送达**对象 → Alt-3
- Exp-A 显示**集中在 arena 0**,Exp-D 显示**大量线程在 cond_wait** → **主线程在涨,worker 都闲着** → 完全推翻 worker 画像,改查初始化路径 / main 上的容器

## R1.6 Exp-E:dlopen 是否在继续加载

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

## R1.7 跑完后的修订表

填这张表,然后再让内部模型扫源码:

| 维度 | 数据 | 修订后约束 |
|---|---|---|
| arena 分布 (Exp-A) | max/avg = ?× | 锁定单 arena / 主线程 / 均匀 worker 之一 |
| 大段 (Exp-B) | 三段 ΔRSS = ? | 锁定 multi-small-object / single-large-object / pool 之一 |
| in-use 分布 (Exp-C,可选) | 直方图主峰 = ? | 锁定累积对象的真实 size 范围 |
| 线程行为 (Exp-D) | 等待/工作/IO 比例 | 锁定背压 vs 真稳态产生 |
| dlopen (Exp-E) | .so 是否在涨 | 是/否 — 决定要不要查 Alt-7 |
| 嫌疑 tid (Exp-F, Round 2) | tid + entry function | 锁定单一线程的代码区间,而非全代码库 |

**修订后画像 = 原 handoff §3 约束 ∩ 上面新增约束**。

修订后给审查方的 prompt 可能从"long-lived 容器小对象漏 erase"改成:

- "**主线程**(arena 0)上的 long-lived 容器,对象**平均 4-16 KB**,触发频率每秒几十次"
- 或:"**所有 worker 均匀贡献**,但栈显示大部分线程在等 — 找**消费速度跟不上 producer** 的队列"
- 或:"**单个**大对象在某段里持续 append,找业务里反复 `+=` / `push_back` 的位置"
- 或:"slab size = 256 B 的 pool allocator 在涨 — 找业务里的 `boost::pool` / 自定义 arena"

## R1.8 决策树(已合并 Round 2 / Round 3 分支)

```
Exp-A 跑完
 ├─ max/avg < 2×        → 画像保留;继续 Exp-B/D/E 验证
 ├─ max/avg 2-10×       → 画像收紧到"少数热 worker"
 ├─ max/avg > 10×       → 单线程集中,必须做 Round 2 Exp-F 映射 tid
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

进程被重启(任意时刻发生)
 └─ 跳到 Round 3 — 重启诊断窗口 playbook
```

跑完上述,再决定:

- 画像不变 → 用原 handoff §3 给内部模型
- 画像变了 → 改 handoff §3,再扫
- 矛盾出现 → 回头检查 Phase 0 数据完整性

---

## 配套文件

- 方法论 skill:`.claude/skills/cpp-memleak/SKILL.md`(本手册属于 Phase 2-3 之间的细化步骤)
- 完整诊断过程:`docs/cpp_aarch64_memleak_investigation.md`
- 源码审查交接:`docs/cpp_memleak_source_review_handoff.md`(其 §3 约束在本手册之后会被修订)
- 本文:`docs/cpp_memleak_constraint_experiments.md`
