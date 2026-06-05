# LD_PRELOAD wrapper 验证 — 已知 leak 测试程序

> 在拿 wrapper 去 simultor 上跑之前,先用这个测试程序**验证 wrapper 能正确抓到 leak**。
> 已知:每秒漏 1000 个 32 字节对象;5 秒漏 ~150 KB。
> 验证目标:wrapper 的 dump top-1 应当是 `inner_leak` 这条 stack,outstanding 应该是 ~150 KB(跑 5 秒后)。

---

## 测试程序源码 — `leak_test.c`

```c
// leak_test.c
// 编译: gcc -O0 -g -o leak_test leak_test.c -lpthread
// 运行: LD_PRELOAD=/tmp/malloc_track.so ./leak_test
// 触发 dump: kill -SIGUSR1 <pid>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 已知 leak 点:这个 stack 应该是 dump 的 top 1
__attribute__((noinline))
static void inner_leak(int size) {
    void *p = malloc(size);
    memset(p, 0xAB, size);  // 用一下,防止 OPT 优化掉
    // 故意不 free
    (void)p;
}

__attribute__((noinline))
static void leaker_thread_fn(int size) {
    // 多一层栈,方便 backtrace 区分
    inner_leak(size);
}

// 第二个 leak 点(更少量),验证 top-2 排序
__attribute__((noinline))
static void small_leak(void) {
    char *p = malloc(8);  // 8 字节,更小
    (void)p;
}

// 正常的 alloc + free,验证 wrapper 不会误报
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
        // 主 leak 点:每个 cycle 漏 1 个 32-byte 对象,1000 Hz
        for (int i = 0; i < 1000; i++) {
            leaker_thread_fn(32);
        }
        // 次 leak 点:漏 1 个 8-byte,100 Hz
        for (int i = 0; i < 100; i++) {
            small_leak();
        }
        // 正常路径:alloc 1000 个 128-byte 然后全部 free
        normal_alloc_free(1000);

        usleep(1000 * 1000);  // 1 秒
    }
    return NULL;
}

int main(void) {
    printf("pid=%d\n", getpid());
    printf("send SIGUSR1 to dump: kill -SIGUSR1 %d\n", getpid());

    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);

    pthread_join(t, NULL);
    return 0;
}
```

## 编译 + 运行

```bash
# 1. 编 wrapper(如果还没编)
gcc -shared -fPIC -O2 -o /tmp/malloc_track.so malloc_track.c -ldl -lpthread

# 2. 编测试程序(-O0 -g 让符号好认)
gcc -O0 -g -o /tmp/leak_test leak_test.c -lpthread

# 3. 跑(LD_PRELOAD 注入 wrapper)
LD_PRELOAD=/tmp/malloc_track.so /tmp/leak_test &
PID=$!

# 4. 等 5 秒让 leak 累积一些
sleep 5

# 5. 触发 dump
kill -SIGUSR1 $PID
sleep 1

# 6. 看 dump
cat /tmp/alloc_track.$PID

# 7. 把 frame addr 翻成函数名
awk '/frame\[/ {print $4}' /tmp/alloc_track.$PID | sort -u | while read addr; do
    echo "$addr  $(addr2line -e /tmp/leak_test -f -C $addr 2>/dev/null)"
done

# 8. 杀掉测试程序
kill $PID
```

## 预期 dump 结果(验证 wrapper 工作正常)

跑 5 秒后,`/tmp/alloc_track.<pid>` 应该长这样:

```
=== alloc_track dump pid=XXXX ===
Top 30 allocation stacks by outstanding bytes:

[#1] outstanding=160000 bytes (5000 live alloc, 5000 total)
    frame[0] = 0x...  → malloc (wrapper)
    frame[1] = 0x...  → inner_leak at leak_test.c:11
    frame[2] = 0x...  → leaker_thread_fn at leak_test.c:18
    frame[3] = 0x...  → worker at leak_test.c:42
    frame[4] = 0x...  → start_thread (libc)
    ...

[#2] outstanding=4000 bytes (500 live alloc, 500 total)
    frame[0] = 0x...  → malloc (wrapper)
    frame[1] = 0x...  → small_leak at leak_test.c:24
    ...
```

### 验证清单

| 项 | 预期 | 不符合 = wrapper 有 bug |
|---|---|---|
| top 1 stack 包含 `inner_leak` | ✓ | `inner_leak` 应该在 frame[1] 或 frame[2] |
| top 1 outstanding ≈ 5000 × 32 = 160 KB | ✓ | 5 秒 × 1000 Hz × 32 B = 160000 字节 |
| top 1 live alloc = total | ✓ | 没释放过,应该相等(说明 wrapper 在记 alloc 但 free 没减 → 全 outstanding) |
| top 2 包含 `small_leak`,outstanding ≈ 500 × 8 = 4 KB | ✓ | 8 字节 × 100 Hz × 5 sec |
| `normal_alloc_free` **不**出现在 top 30 | ✓ | 所有 128-byte 都 free 了,outstanding 应该为 0,不进 dump |
| addr2line 解析后能看到 `leak_test.c:11` | ✓ | 符号 + 行号都对得上 |

## 如果验证不通过

| 现象 | 可能原因 | 修法 |
|---|---|---|
| dump 文件不存在 | wrapper 的 SIGUSR1 handler 没注册 | 检查 `__attribute__((constructor)) setup` 是否在 wrapper 里 |
| dump 是空的 / 只有 header | wrapper 在 `inside` 递归保护时丢了所有记录 | 调试 `inside` 标志路径 |
| top 1 不是 `inner_leak` | backtrace 失败或栈帧不准 | 加 `-fno-omit-frame-pointer` 重编测试程序;检查 backtrace 深度 |
| `normal_alloc_free` 也出现在 top | free 路径没正确减 outstanding | 检查 `ptr_table` 的 free 处理逻辑 |
| outstanding 数字明显不对 | 哈希冲突合并了不同 stack | 增大 `STACK_BUCKETS`,或换更好的 hash |
| segfault | wrapper 自身的 malloc 递归 / NULL 指针 | `inside` thread-local 没生效;dlsym 时序问题 |

修好之后再去 simultor 上跑。

## 走完测试之后

确认 wrapper OK 了,**再去 simultor 上跑**:

```bash
# 业务跑前
LD_PRELOAD=/tmp/malloc_track.so /path/to/simultor [args...] &
PID=$!

# 业务跑 30-60 min(让 168 MB/h × 1 h ≈ 168 MB 累积)
sleep 3600

# dump
kill -SIGUSR1 $PID

# 看 top stacks
cat /tmp/alloc_track.$PID

# addr2line 解析
awk '/frame\[/ {print $4}' /tmp/alloc_track.$PID | sort -u | while read addr; do
    echo "$addr  $(addr2line -e /path/to/simultor -f -C $addr 2>/dev/null)"
done
```

**top 3 stack 几乎 100% 命中真嫌疑代码**。
