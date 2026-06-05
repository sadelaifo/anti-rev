# LD_PRELOAD Wrapper 单页 Playbook(从零到 leak 真嫌疑,~1 小时)

> 自包含。两份源码都内嵌。从板上 gcc 开始,到拿出 simultor 的真 leak stack。

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
SIMULTOR_BIN=/path/to/simultor   # 业务 binary
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
