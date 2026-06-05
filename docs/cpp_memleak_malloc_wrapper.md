# LD_PRELOAD malloc wrapper — ground-truth leak 定位

> **目的**:不依赖源码推理,直接抓"谁在 malloc 但不 free"的真实 stack。
> **代价**:写 150 行 C(2-4 小时)+ 一次重启 + 跑 1 小时业务。
> **产出**:top N stack(按 outstanding bytes 排序),addr2line 一遍就是真嫌疑代码。
>
> 适用场景:**snapshot diff 已经描述清楚 leak(速率、scope、稳态)但没法定位具体代码**。

---

## 1. 设计

```
malloc/free 包装层
├─ 拦截 malloc → 真实 __libc_malloc + 抓 backtrace(6 帧)
├─ 拦截 free   → 真实 __libc_free + 减回桶字节数
└─ 维护两张表:
    ├─ stack_table:  stack_hash → { count, total_outstanding_bytes, frames[6] }
    └─ ptr_table:    ptr        → { size, stack_hash }     (用于 free 时反查)
```

收到 SIGUSR1 → dump stack_table 按 outstanding_bytes 排序的 top-N 到文件。

## 2. 实现(自包含,板上 gcc 直接编)

```c
// malloc_track.c
// 编译: gcc -shared -fPIC -O2 -o malloc_track.so malloc_track.c -ldl -lpthread
// 使用: LD_PRELOAD=./malloc_track.so ./your_program
// dump:  kill -SIGUSR1 $PID
//        会写到 /tmp/alloc_track.<pid>

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
#define STACK_BUCKETS  4096   // 哈希桶数,2 的幂
#define PTR_BUCKETS    (1<<20) // 1M 桶,容纳 100M 活对象
#define DUMP_TOP_N     30

typedef struct stack_entry {
    uint64_t        hash;
    void           *frames[STACK_DEPTH];
    uint64_t        count;             // 当前未释放的 alloc 数
    uint64_t        outstanding_bytes; // 当前未释放的总字节数
    uint64_t        total_alloc_count; // 累计 alloc 次数(含已释放)
    struct stack_entry *next;          // 同桶链
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
static __thread int inside = 0;  // 防止 backtrace 内部 malloc 递归

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

    // 收集所有 stack entry
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

    fflush(f);
    fclose(f);
    // dprintf 直接写 stderr 一行通知
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

## 3. 用法

```bash
# 1. 编译(板上 gcc)
gcc -shared -fPIC -O2 -o /tmp/malloc_track.so malloc_track.c -ldl -lpthread

# 2. 跑业务(用 LD_PRELOAD 注入)
LD_PRELOAD=/tmp/malloc_track.so ./simultor   # 替换成你的业务命令

# 3. 业务跑 30-60 分钟,让 leak 真实积累
sleep 1800

# 4. 触发 dump
kill -SIGUSR1 $PID
# 看 /tmp/alloc_track.<PID>

# 5. 解析 stack(addr2line)
# 假设业务 binary = /path/to/simultor
awk '/frame\[/ {print $4}' /tmp/alloc_track.$PID | sort -u | while read addr; do
    echo "$addr  $(addr2line -e /path/to/simultor -f -C $addr 2>/dev/null)"
done
```

## 4. 看 dump 怎么判读

```
[#1] outstanding=1543264800 bytes (3082530 live alloc, 5670123 total)
    frame[0] = 0x7f1234567890
    frame[1] = 0x7f1234abcdef
    frame[2] = 0x7f1234fedcba
    ...
```

- **outstanding bytes** = 当前未释放的总字节,**排序第一名通常就是 leak 源**
- **live alloc** = 当前未释放的对象数;**对比 total** 看泄漏比例(live/total 接近 1 = 全漏;接近 0 = 临时分配)
- **frame[0]** 是 caller(最近的调用者),frame[1..5] 是更深的栈

用 addr2line 把 frame addr 转回 `file:line + function`,**top 3 个 stack 几乎 100% 命中真嫌疑**。

## 5. 注意事项

1. **栈深 6 帧**:够区分大部分场景。模板继承多层可调到 8;太深会失真(尾帧重合)
2. **桶大小**:`STACK_BUCKETS=4096` 假设不超过 4K 不同的分配 stack。业务复杂可加到 16384
3. **`inside` thread-local**:防止 backtrace 自身的 malloc 递归
4. **fastbin 影响**:用 LD_PRELOAD 后 glibc 仍走 ptmalloc,但小对象会绕过 fastbin 路径(因为我们 hook 了 malloc),性能稍降但可以接受
5. **跑业务多久**:30 min - 1 h 通常够;若 leak 慢可跑 2 h
6. **dump 文件大小**:~30 KB,可忽略

## 6. 跟之前 8 轮诊断的关系

- 之前外部诊断**告诉你"leak 在,速率 168 MB/h"**(描述层)
- 本 wrapper **告诉你"在这条 stack"**(定位层)
- 两者**互补不冲突**;wrapper 出的 top stack 应该能用 168 MB/h 反算合理(top stack 的 outstanding_bytes / 运行时长 ≈ 168 MB/h)

## 7. 不该用 wrapper 的情况

- 业务对 syscall 时延敏感(wrapper 每次 malloc 加 ~微秒级开销)→ 用 jemalloc prof
- 业务有自己的 allocator(直接调 sbrk/mmap 不走 malloc)→ wrapper 抓不到
- 业务被沙箱限制 LD_PRELOAD → 用 gcore + 离线 heap walker

否则,**LD_PRELOAD wrapper 是 C++ leak 定位的瑞士军刀**。
