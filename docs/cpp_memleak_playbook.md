# LD_PRELOAD Wrapper 单页 Playbook(从零到 leak 真嫌疑,~1 小时)

> 自包含。两份源码都内嵌。从板上 gcc 开始,到拿出 simultor 的真 leak stack。

---

## 跑之前的 5 项检查(< 2 分钟)

```bash
# 1. 板上 gcc 可用
gcc --version | head -1

# 2. addr2line 可用(后面解析 frame 用)
which addr2line

# 3. /tmp 可写,有空间(dump 几十 KB,日志几 MB)
df -h /tmp | tail -1

# 4. 业务 binary 路径(后面 addr2line 要)
ls -la /path/to/simultor

# 5. 业务 binary 有没有符号(没符号 frame 全是 ??,要拷未 strip 版本)
file /path/to/simultor   # 看 "stripped" 还是 "with debug_info"
nm /path/to/simultor 2>/dev/null | head -5
```

如果业务 binary **strip 过** → 现在就请内部团队**准备一份未 strip 版**(同源、同 commit、同 flags 的 build 产物),否则 Step 10 出来全是 `??` 看不懂。

---

## 准备:在板上建工作目录

```bash
mkdir -p ~/leak_test
cd ~/leak_test
```

把下面两份源码贴成两个文件即可,**不需要外部下载**。

---

## 文件 1:`malloc_track.c`(wrapper,~150 行)

```c
// malloc_track.c — LD_PRELOAD malloc tracker
// 编译: gcc -shared -fPIC -O2 -o malloc_track.so malloc_track.c -ldl -lpthread

#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STACK_DEPTH    6
#define STACK_BUCKETS  4096
#define PTR_BUCKETS    (1<<20)
#define DUMP_TOP_N     30

typedef struct stack_entry {
    uint64_t        hash;
    void           *frames[STACK_DEPTH];
    uint64_t        count;
    uint64_t        outstanding_bytes;
    uint64_t        total_alloc_count;
    struct stack_entry *next;
} stack_entry_t;

typedef struct ptr_entry {
    void               *ptr;
    size_t              size;
    stack_entry_t      *stack;
    struct ptr_entry   *next;
} ptr_entry_t;

static stack_entry_t *stack_buckets[STACK_BUCKETS];
static ptr_entry_t   *ptr_buckets[PTR_BUCKETS];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static void *(*real_malloc)(size_t)  = NULL;
static void  (*real_free)(void*)     = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_realloc)(void*, size_t) = NULL;

static int initialized = 0;
static __thread int inside = 0;

static uint64_t hash_frames(void **frames, int n) {
    uint64_t h = 14695981039346656037ULL;
    for (int i = 0; i < n; i++) {
        h ^= (uint64_t)frames[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void init_real(void) {
    if (initialized) return;
    real_malloc  = dlsym(RTLD_NEXT, "malloc");
    real_free    = dlsym(RTLD_NEXT, "free");
    real_calloc  = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    initialized = 1;
}

static stack_entry_t *get_or_create_stack(void **frames, int n, uint64_t hash) {
    size_t b = hash & (STACK_BUCKETS - 1);
    stack_entry_t *e = stack_buckets[b];
    while (e) {
        if (e->hash == hash) return e;
        e = e->next;
    }
    e = real_malloc(sizeof(*e));
    if (!e) return NULL;
    e->hash = hash;
    memcpy(e->frames, frames, sizeof(void*) * STACK_DEPTH);
    e->count = 0;
    e->outstanding_bytes = 0;
    e->total_alloc_count = 0;
    e->next = stack_buckets[b];
    stack_buckets[b] = e;
    return e;
}

static void track_alloc(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    if (inside) return;
    inside = 1;

    void *frames[STACK_DEPTH];
    int n = backtrace(frames, STACK_DEPTH);
    uint64_t h = hash_frames(frames, n);

    pthread_mutex_lock(&mu);
    stack_entry_t *s = get_or_create_stack(frames, n, h);
    if (s) {
        s->count++;
        s->outstanding_bytes += size;
        s->total_alloc_count++;
    }
    ptr_entry_t *p = real_malloc(sizeof(*p));
    if (p) {
        p->ptr = ptr;
        p->size = size;
        p->stack = s;
        size_t b = ((uintptr_t)ptr >> 4) & (PTR_BUCKETS - 1);
        p->next = ptr_buckets[b];
        ptr_buckets[b] = p;
    }
    pthread_mutex_unlock(&mu);
    inside = 0;
}

static void track_free(void *ptr) {
    if (!ptr) return;
    if (inside) return;
    inside = 1;

    size_t b = ((uintptr_t)ptr >> 4) & (PTR_BUCKETS - 1);
    pthread_mutex_lock(&mu);
    ptr_entry_t **pp = &ptr_buckets[b];
    while (*pp) {
        if ((*pp)->ptr == ptr) {
            ptr_entry_t *p = *pp;
            if (p->stack) {
                p->stack->count--;
                p->stack->outstanding_bytes -= p->size;
            }
            *pp = p->next;
            real_free(p);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&mu);
    inside = 0;
}

void *malloc(size_t size) {
    init_real();
    void *p = real_malloc(size);
    track_alloc(p, size);
    return p;
}

void free(void *ptr) {
    init_real();
    track_free(ptr);
    real_free(ptr);
}

void *calloc(size_t n, size_t s) {
    init_real();
    void *p = real_calloc(n, s);
    track_alloc(p, n * s);
    return p;
}

void *realloc(void *old, size_t size) {
    init_real();
    if (old) track_free(old);
    void *p = real_realloc(old, size);
    if (p) track_alloc(p, size);
    return p;
}

static int cmp_outstanding_desc(const void *a, const void *b) {
    stack_entry_t *sa = *(stack_entry_t**)a;
    stack_entry_t *sb = *(stack_entry_t**)b;
    if (sb->outstanding_bytes > sa->outstanding_bytes) return 1;
    if (sb->outstanding_bytes < sa->outstanding_bytes) return -1;
    return 0;
}

static void dump_handler(int sig) {
    (void)sig;
    char path[64];
    snprintf(path, sizeof(path), "/tmp/alloc_track.%d", getpid());
    FILE *f = fopen(path, "w");
    if (!f) return;

    pthread_mutex_lock(&mu);
    stack_entry_t **all = real_malloc(sizeof(void*) * STACK_BUCKETS * 64);
    if (!all) { pthread_mutex_unlock(&mu); fclose(f); return; }
    int n_all = 0;
    for (int i = 0; i < STACK_BUCKETS; i++) {
        for (stack_entry_t *e = stack_buckets[i]; e; e = e->next) {
            if (e->outstanding_bytes > 0) {
                all[n_all++] = e;
            }
        }
    }
    qsort(all, n_all, sizeof(void*), cmp_outstanding_desc);

    int n_dump = n_all < DUMP_TOP_N ? n_all : DUMP_TOP_N;
    fprintf(f, "=== alloc_track dump pid=%d ===\n", getpid());
    fprintf(f, "Top %d allocation stacks by outstanding bytes:\n\n", n_dump);
    for (int i = 0; i < n_dump; i++) {
        stack_entry_t *e = all[i];
        fprintf(f, "[#%d] outstanding=%lu bytes (%lu live alloc, %lu total)\n",
                i + 1, e->outstanding_bytes, e->count, e->total_alloc_count);
        for (int j = 0; j < STACK_DEPTH; j++) {
            if (e->frames[j])
                fprintf(f, "    frame[%d] = %p\n", j, e->frames[j]);
        }
        fprintf(f, "\n");
    }
    real_free(all);
    pthread_mutex_unlock(&mu);

    fflush(f); fclose(f);
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "[malloc_track] dump written to %s\n", path);
    write(2, buf, n);
}

__attribute__((constructor))
static void setup(void) {
    init_real();
    signal(SIGUSR1, dump_handler);
}
```

---

## 文件 2:`leak_test.c`(已知 leak 测试程序)

```c
// leak_test.c — 已知 leak 量的测试程序,验证 wrapper 行为
// 编译: gcc -O0 -g -o leak_test leak_test.c -lpthread

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline))
static void inner_leak(int size) {
    void *p = malloc(size);
    memset(p, 0xAB, size);
    (void)p;  // 故意不 free
}

__attribute__((noinline))
static void leaker_thread_fn(int size) {
    inner_leak(size);
}

__attribute__((noinline))
static void small_leak(void) {
    char *p = malloc(8);
    (void)p;
}

__attribute__((noinline))
static void normal_alloc_free(int n) {
    for (int i = 0; i < n; i++) {
        void *p = malloc(128);
        free(p);
    }
}

void *worker(void *arg) {
    (void)arg;
    while (1) {
        for (int i = 0; i < 1000; i++) leaker_thread_fn(32);  // 主 leak,1000 Hz × 32 B
        for (int i = 0; i < 100; i++)  small_leak();           // 次 leak,100 Hz × 8 B
        normal_alloc_free(1000);                                // 正常 alloc+free,不该出现在 dump
        usleep(1000 * 1000);
    }
    return NULL;
}

int main(void) {
    printf("pid=%d  send: kill -SIGUSR1 %d\n", getpid(), getpid());
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    return 0;
}
```

---

## 10 步 playbook

### Step 1 — 编译 wrapper(30 sec)

```bash
cd ~/leak_test
gcc -shared -fPIC -O2 -o malloc_track.so malloc_track.c -ldl -lpthread
ls -la malloc_track.so   # 应该看到 .so 生成
```

### Step 2 — 编译测试程序(1 min)

```bash
gcc -O0 -g -o leak_test leak_test.c -lpthread
ls -la leak_test
```

### Step 3 — 启动测试(LD_PRELOAD 注入 wrapper)

```bash
LD_PRELOAD=$PWD/malloc_track.so ./leak_test &
PID=$!
echo "test pid = $PID"
```

### Step 4 — 等 5 秒 + 触发 dump

```bash
sleep 5
kill -SIGUSR1 $PID
sleep 1   # 让 dump 写完
```

### Step 5 — 看 dump,验证 top stack 是 inner_leak

```bash
cat /tmp/alloc_track.$PID
```

**预期看到**:

```
=== alloc_track dump pid=XXXX ===
Top 30 allocation stacks by outstanding bytes:

[#1] outstanding=160000 bytes (5000 live alloc, 5000 total)
    frame[0] = 0x...
    frame[1] = 0x...  ← inner_leak
    frame[2] = 0x...  ← leaker_thread_fn
    ...

[#2] outstanding=4000 bytes (500 live alloc, 500 total)
    frame[1] = 0x...  ← small_leak
    ...
```

**关键校验**:

| 项 | 预期值 | 不符合 |
|---|---|---|
| top 1 outstanding ≈ 160 KB | (5 sec × 1000 Hz × 32 B) | wrapper 没在抓 alloc |
| top 1 live == total | (没释放过) | free 路径有问题 |
| top 2 outstanding ≈ 4 KB | (5 sec × 100 Hz × 8 B) | 哈希冲突合并了不同 stack |
| `normal_alloc_free` **不**在 top 30 | (全都 free 了) | free 路径没在减 outstanding |

### Step 6 — addr2line 解析 frame,确认 file:line 对得上

```bash
awk '/frame\[/ {print $4}' /tmp/alloc_track.$PID | sort -u | while read addr; do
    echo "$addr  $(addr2line -e ./leak_test -f -C $addr 2>/dev/null)"
done
```

**预期看到**:某个 frame 解析为 `inner_leak at leak_test.c:11` 之类。如果全部是 `??` → 测试程序没带 debug info,加 `-g` 重编。

杀掉测试:

```bash
kill $PID
rm /tmp/alloc_track.$PID
```

---

### ━━━━━━━━━━ 工具验证完毕,开始真嫌疑捕捉 ━━━━━━━━━━

### Step 7 — 用 wrapper 启 simultor

```bash
# 替换成你的 simultor 启动命令(含 4 plugin 加载参数)
LD_PRELOAD=$PWD/malloc_track.so /path/to/simultor [args...] &
PID=$!
echo "simultor pid = $PID"
```

> 注意:如果 simultor 是被某个 wrapper / supervisor 拉起的,把 `LD_PRELOAD=$PWD/malloc_track.so` 加到那个 wrapper 的环境变量里,**确保业务进程真的看到这个 env**。
>
> 验证 LD_PRELOAD 生效:
> ```bash
> tr '\0' '\n' < /proc/$PID/environ | grep PRELOAD
> grep malloc_track /proc/$PID/maps   # 应该看到 .so 被 map 进去
> ```

### Step 8 — 业务正常跑 30-60 min,让 leak 累积 ~84-168 MB

```bash
# 按 Tier 1 速率 168 MB/h:
# - 30 min ≈ 84 MB outstanding(够区分嫌疑和噪声)
# - 60 min ≈ 168 MB outstanding(信号清晰)
sleep 3600
```

### Step 9 — 触发 dump

```bash
kill -SIGUSR1 $PID
sleep 1
cat /tmp/alloc_track.$PID | head -100
```

### Step 10 — addr2line 解析 top 3 stack,**就是真嫌疑代码**

```bash
SIMULTOR_BIN=/path/to/simultor   # 业务 binary(最好未 strip)
awk '/frame\[/ {print $4}' /tmp/alloc_track.$PID | sort -u | while read addr; do
    echo "$addr  $(addr2line -e $SIMULTOR_BIN -f -C $addr 2>/dev/null)"
done > /tmp/leak_resolved.txt
less /tmp/leak_resolved.txt
```

**对照 dump 看**:

- `[#1]` 的 outstanding 估算速率(`outstanding / 3600 sec`)→ 跟 168 MB/h 是不是一致?是的话 top 1 就是主 leak
- top 1 的 frame[1..5] 在 `/tmp/leak_resolved.txt` 里的对应 file:line → **改这里的代码**

如果 frame 全是 `??`(simultor binary 也 strip 过):
- 拿到 dev 机上用未 strip 的 simultor binary 跑 addr2line
- 或用 `nm` / `objdump -d` 反查地址附近的符号

---

## Step 10.5 — 怎么读 top stack(几种情形)

dump 出来 top 3 大概率落在以下几种 pattern,**对应不同结论**:

| top stack 形态(frame[0..5] 解析后) | 含义 | 修法方向 |
|---|---|---|
| frame[0] = `malloc`, frame[1..5] **全在 plugin 业务代码**(如 `MyPlugin::Foo::handle`) | **纯 plugin leak** | 内部模型 re-review 那个具体函数,找 `push` 没 `erase` |
| frame[0..1] = `malloc` + `libgrpc.so` 或 `libprotobuf.so`,**frame[2..5] 回到 plugin 代码** | **plugin 错误使用框架对象**(B 情形,最常见) | plugin 在 new/Arena/subscribe 框架对象后没释放;查 frame[2] 所在 plugin 函数的 long-lived 对象 |
| frame[0..5] **全在 `libgrpc` / `libprotobuf` / `libabsl`** 内部 | **框架内部 leak**(A 情形,较少) | 升级框架版本 / 检查 gRPC channel arg 配置 / 用 `GRPC_ARG_*` 调超时 |
| frame[0..1] = `malloc` + `libstdc++.so`(如 `std::string` / `std::map`), frame[2..5] 在 plugin | **plugin 的容器单调累积** | 找该容器的 erase 路径,看 combo-dependent 触发 |
| frame[0..2] 在 **simultor 平台代码**(不在 plugin) | **平台 leak 不在 plugin** | 内部模型扫 simultor 而不是 4 plugin |
| top 1-3 outstanding 都很小(< 10% ΔRSS) | 没有"单一大头",**leak 分散在很多 stack** | 看 top 30,找语义相同的多个 stack 合并(都属同模块就是该模块的问题) |

**关键规则**:**永远看 frame[1..5] 而不只是 frame[0]**。frame[0] 是 `malloc` 本身,意义不大;frame[1] 才是直接调用者;frame[2..5] 沿着调用链上溯找语义。

## Step 11(可选)— 多时点 dump 看趋势

跑过程中可以**多次 `kill -SIGUSR1`**,每次 dump 都会覆盖 `/tmp/alloc_track.$PID`。建议:

```bash
# 30 min dump
sleep 1800
kill -SIGUSR1 $PID
cp /tmp/alloc_track.$PID /tmp/alloc_track.$PID.30min

# 60 min dump
sleep 1800
kill -SIGUSR1 $PID
cp /tmp/alloc_track.$PID /tmp/alloc_track.$PID.60min

# 对比看 top 1 outstanding 是不是按 ΔRSS 比例涨
diff <(grep outstanding /tmp/alloc_track.$PID.30min) \
     <(grep outstanding /tmp/alloc_track.$PID.60min)
```

top 1 outstanding 从 30 min 到 60 min **应该接近翻倍** —— 这是它确实是 leak 源的强证据(而不是"启动时一次性分配")。

---

## 关键检测:wrapper 抓到的够不够?(不是 malloc 怎么办)

wrapper 只能抓 `malloc / calloc / realloc / free`。如果业务的 leak 走**别的路径**(`mmap`、`shmget`、JIT、线程栈、文件映射等),wrapper 会**抓不全**。

**Step 9.5 — 检测 wrapper 抓全没**(强烈建议跑):

```bash
# wrapper 抓到的 outstanding 总和
WRAPPER_TOTAL=$(awk -F'[ =]' '/outstanding=/ {sum += $3} END {print sum}' /tmp/alloc_track.$PID)
echo "wrapper outstanding total = $((WRAPPER_TOTAL / 1024 / 1024)) MB"

# 实际 RSS 增量(LD_PRELOAD 启动到 dump 之间)
echo "请手动确认 ΔRSS:启动时 RSS vs 现在 RSS"
grep VmRSS /proc/$PID/status
```

| WRAPPER_TOTAL / ΔRSS | 含义 | 下一步 |
|---|---|---|
| **> 70%** | leak 在 malloc 路径,wrapper 抓全了 | Step 10 解析 top stack 即可 |
| **30-70%** | malloc 一部分 + 其他路径一部分 | Step 10 + 下面 Plan A 或 B |
| **< 30%** | leak NOT in malloc | 跳过 Step 10,直接走 Plan A/B/C |

### Plan A — 扩展 wrapper 加 mmap 跟踪

在 `malloc_track.c` 加这两段:

```c
// 加在顶部
#include <sys/mman.h>

static void *(*real_mmap)(void*, size_t, int, int, int, off_t) = NULL;
static int (*real_munmap)(void*, size_t) = NULL;

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");
    void *p = real_mmap(addr, length, prot, flags, fd, offset);
    // 只跟匿名 + 私有 mmap(过滤文件映射、共享内存)
    if (p != MAP_FAILED && (flags & MAP_ANONYMOUS) && (flags & MAP_PRIVATE) && fd < 0) {
        track_alloc(p, length);
    }
    return p;
}

int munmap(void *addr, size_t length) {
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
    track_free(addr);
    return real_munmap(addr, length);
}
```

重编 wrapper 再跑一遍 Step 7-10。

**注意**:LD_PRELOAD 拦不到 glibc 内部 `mmap`(它走 vdso 或直接 syscall),所以不会跟 malloc 的内部 mmap 冲突。**只会捕获业务代码显式 `mmap()` 调用**。

### Plan B — pmap diff 找新增 mmap 段(不重启)

```bash
# wrapper 跑业务前
pmap -x $PID > /tmp/pmap_before.txt

# 跑 30 分钟业务

# wrapper 跑业务后
pmap -x $PID > /tmp/pmap_after.txt

# 找新增的大段(> 1 MB)
diff /tmp/pmap_before.txt /tmp/pmap_after.txt | grep -E '^>' | awk '$3 > 1000'
```

新增段的**地址 + 大小**就是 mmap 的产物。再用 strace 抓哪个 syscall 创建的:

```bash
# 抓后续的 mmap 调用,带 stack
strace -p $PID -e mmap,munmap -f -k 2>&1 | head -50
```

`-k` 在新版 strace 里打印 stack(老版没这个,只能看 syscall args 推 caller)。

### Plan C — 各种 fallback

| 工具 | 适用 |
|---|---|
| `ltrace` | 跟 libc / 其他库调用,看业务用了哪些 alloc API |
| eBPF `funccount` / `funclatency` | 板上有 bcc 才行 |
| `gcore` + 离线 | core 文件里能看每个 VMA 的实际数据,推断来源 |
| 直接看 `/proc/PID/smaps` | 大段的 `Anonymous` / `Shared_Clean` / `Private_Dirty` 分类能区分类型 |

## 故障排查

| 现象 | 原因 | 修法 |
|---|---|---|
| Step 3 起不来,报 `undefined symbol: backtrace` | wrapper 链接缺 libc | gcc 加 `-rdynamic` |
| Step 5 dump 文件不存在 | SIGUSR1 handler 没注册 | 检查 wrapper 的 `__attribute__((constructor))` |
| Step 5 dump 是空 | 全在 `inside` 递归保护 | 调试 `inside` 标志,加打印看流程 |
| Step 6 全是 `??` | 测试程序没带 debug info | 重编时确认 `-g` |
| Step 7 LD_PRELOAD 没生效 | 业务被 setuid / sandbox / wrapper 吃掉 env | 看 `/proc/PID/environ` 确认;改 wrapper 启动方式 |
| Step 9 dump 文件很大但 top 1 outstanding 远小于预期 | 哈希冲突 / wrapper bug | `STACK_BUCKETS` 加大到 16384;或检查 `track_free` 逻辑 |
| Step 10 frame 全是 `??` | simultor binary 没符号 | 用 dev 机的未 strip 版本跑 addr2line |
| 进程 segfault | wrapper 内 malloc 递归;dlsym 时序 | `inside` 标志没生效;检查 `init_real` 调用时机 |
| Step 9 SIGUSR1 后业务挂住几秒 | dump_handler 在 signal context 跑 `fopen/fprintf`,严格说不 async-signal-safe;有些 stdio 状态冲突会让业务卡 | 通常会自己恢复;若反复挂起,把 dump_handler 改为只置一个 flag,另起线程轮询 flag 后做 fopen 写 |
| Step 7 simultor 是被 supervisor / systemd 拉起 | env 在父进程加 LD_PRELOAD,但 systemd unit / shell wrapper 可能 sanitize 掉 | 把 `LD_PRELOAD=...` 写进 simultor 的 wrapper 脚本 / systemd unit 的 `Environment=`;或者改写 systemd 启动入口 |
| simultor 是静态链接的 binary | LD_PRELOAD 对静态 binary **完全无效** | 必须重新动态链接业务,或换 gcore + 离线分析 |

---

## 总结

```
Step 1-2  编译 wrapper + 测试程序        (~2 min)
Step 3-6  验证 wrapper 行为正常          (~2 min)
Step 7    LD_PRELOAD 启动 simultor       (~10 sec)
Step 8    业务跑 30-60 min               (~60 min)
Step 9    SIGUSR1 dump                   (~10 sec)
Step 10   addr2line 解析 top 3 stack     (~5 min)
                                          ─────
                                          ~70 min
```

跑完一遍,**top 3 stack 几乎 100% 命中真嫌疑代码**。把 `/tmp/leak_resolved.txt` 贴回来,我帮看是哪几条业务路径。
