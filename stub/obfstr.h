/*
 * obfstr.h — string-literal obfuscation for antirev components.
 *
 * ─── 威胁模型 ─────────────────────────────────────────────────────────
 *
 * antirev 把磁盘上的保护二进制加密了.  但 stub 启动时把它解到 memfd,
 * memfd 立刻被映射进进程地址空间 -- 这时 `strings /proc/<PID>/maps`
 * (或对 memfd 文件本身 strings) 能看到源码里所有的字符串字面量:
 *
 *      printf 格式串       "[antirev] failed to connect to lib daemon"
 *      perror 错误消息     "memfd_create"
 *      env-var 名          "ANTIREV_LIBD_SOCK="  "ANTIREV_FD_MAP="
 *      dlsym 符号名        "ANTI_LoadProcess"  "popen"  "openat"
 *      路径模板            "/proc/self/fd/%d"  "/tmp/.antirev-..."
 *      socket 名前缀       "antirev_%s"
 *
 * 整套反逆向架构特征对静态分析者裸奔.  obfstr 让这些字面量在 .rodata
 * 里也以异或后的密文存在, 仅在调用时短暂解到栈上一份明文.
 *
 * ─── 整体架构 (两阶段) ─────────────────────────────────────────────────
 *
 *      源码 (stub/*.c)
 *          │   perror("memfd_create");
 *          │   fprintf(stderr, "[antirev] failed");
 *          │   dlsym(RTLD_NEXT, "ANTI_LoadProcess");
 *          ▼
 *      [1] tools/obfstr_gen.py            ← 编译期, gcc 之前跑
 *          │   扫描调用, 识别字面量参数, 异或加密
 *          ▼
 *      build/obf/*.c (rewrite 后的源码)
 *          │   perror(_OBF(0x3a, 0x2b, 0x2c, ...));
 *          │   fprintf(stderr, _OBF(0x0c, 0x2f, ...));
 *          │   dlsym(RTLD_NEXT, _OBF(0x16, 0x00, ...));
 *          ▼
 *      [2] gcc 编译  +  本头文件 (运行时解码)
 *          │   密文字节进 .rodata (volatile 防折叠回明文)
 *          ▼
 *      最终二进制 — strings 看到的是噪声字节
 *
 * ─── 阶段 1: tools/obfstr_gen.py ──────────────────────────────────────
 *
 * CMake 在编译每个 stub/*.c 之前先跑这个 Python 脚本, 输出 rewrite 版
 * 到 build/obf/<basename>.  脚本对一组已知函数/宏做模式扫描:
 *
 *      antirev 包装宏:    OBFSTR LOG_ERR PERR OSNPRINTF ODLSYM LOG
 *      libc print:        fprintf snprintf perror
 *      libc 符号/环境:    dlsym getenv setenv unsetenv
 *      libc 字符串比较:   strcmp strncmp strstr
 *      libc 文件/exec:    fopen open openat syscall execl/execve/...
 *      项目内 helper:     strip_env_path_entries find_env_value make_memfd
 *
 * 对每个调用站点:
 *   - 解析参数列表 (处理嵌套括号, 字符串拼接 "a" "b", 转义 \n \xNN \ooo)
 *   - 任何纯字符串字面量参数被替换为 _OBF(0xNN, 0xNN, ...)
 *   - 非字面量参数 (变量, 表达式) 原封不动放过
 *
 * 加密公式 (obf_key(i) in obfstr_gen.py):
 *
 *      key(i) = 0x5a XOR (((i * 7) + 13) & 0xff)
 *
 * 位置敏感: 第 i 个字节用第 i 个 key 异或.  encode/decode 用同一公式
 * 所以 codegen 时编码的密文运行时能准确还原.
 *
 * 注意: codegen 只识别 "函数调用参数" 位置的字面量.  以下模式它
 * "看不到", 必须靠源码改造:
 *
 *      static const char *arr[] = {"X", NULL};       // 数组初始化器
 *      const char *p = "X";                          // 全局/局部变量初始化
 *      struct s = {.name = "X"};                     // struct 初始化
 *      out[i] = "X";                                 // 裸赋值
 *      #define MACRO "X"                             // 宏内字面量
 *
 * 项目里这种点都已经手动 wrap 成 OBFSTR("X") (function-call 位置, 被
 * codegen 识别) 或 strdup(OBFSTR("X")) (跨函数边界场景).
 *
 * ─── 阶段 2: 运行时解码 (本头文件) ─────────────────────────────────────
 *
 * _OBF(...) 是个 GCC statement expression, 详见下方实现.  两个关键
 * 设计选择:
 *
 *   ① const volatile uint8_t _e[] -- volatile 是命脉.
 *      没有 volatile, gcc -O2 直接看穿异或、把整个解码循环在编译期
 *      算掉、把明文塞回 .rodata, 整个保护就废了.  volatile 强制每个
 *      字节从内存 load 一次, 禁止 const-folding.
 *
 *   ② __builtin_alloca 分配解码缓冲.
 *      早期版本用 char buf[N] 在 statement expression 块里声明,
 *      老 GCC 在 SE 边界就把这个 buf 标 "作废", 下一次 OBFSTR 调用的
 *      密文数组就把同一栈槽覆盖了 -- 调用方握的指针读到的是别人的
 *      密文.  __builtin_alloca 分配在 *调用函数的栈帧* 上, 跨 SE
 *      边界稳定有效, 函数 return 前都活着.
 *
 * 生命周期约束: 解码 buffer 跟着 *调用函数* 走, 函数 return 前都有效.
 *
 *      fprintf(stderr, OBFSTR("hello"));           ✅ 安全
 *      printf(LOG_ERR_arg, ...);                   ✅ 调用瞬间消费完
 *      const char *p = OBFSTR("x"); later_call(p); ❌ UB — buffer 已死
 *      static const char *p = OBFSTR("x");         ❌ UB — alloca 不能 static
 *
 * 不要把 OBFSTR 的返回指针存到 static / 全局, 也不要跨函数边界传递.
 *
 * ─── 包装宏 (用着方便) ────────────────────────────────────────────────
 *
 * 提供几个语义清晰的宏:
 *
 *      LOG_ERR(fmt, ...)            → fprintf(stderr, fmt, ...)
 *      PERR(msg)                    → "msg: <strerror>\n" to stderr
 *      OSNPRINTF(buf, n, fmt, ...)  → snprintf with obfuscated fmt
 *      ODLSYM(handle, name)         → dlsym(handle, name)
 *
 * 但实际上你不一定要用它们 -- fprintf / snprintf / perror / dlsym
 * 本身就在 codegen 列表, 现存代码不改也能加密.  这些封装只是给后续
 * 新代码一个语义友好的入口.
 *
 * ─── 攻击面覆盖 ────────────────────────────────────────────────────────
 *
 * 能挡:
 *   ✓ 攻击者拿到磁盘上加密 binary, 离线 strings 找信息
 *   ✓ 解密后的 memfd 文件复制出来再 strings
 *   ✓ 进程 core dump 静态分析
 *   ✓ /proc/<PID>/maps 里 .rodata 段做静态 dump
 *
 * 挡不了:
 *   ✗ 攻击者已经能 ptrace 业务进程, 等到 printf 那一刻 dump 栈
 *     (OBFSTR 解出来的瞬间, 明文在 alloca 栈 buffer 里数微秒到数毫秒)
 *   ✗ /proc/<PID>/mem 高频抓快照 -- 同上, 撞上调用瞬间能抓到
 *   ✗ printf 的输出本身 (stdout/stderr/syslog 的 sink)
 *   ✗ 链进来的第三方库 (glibc 错误消息表等) -- 不在我们源码里
 *   ✗ 导出符号名 (ANTI_LoadProcess 等) -- LD_PRELOAD 拦截要求 .dynsym
 *     里必须出现这个名字, 否则链接器找不到拦截入口
 *   ✗ 编译器/链接器自动注入的字符串 (.comment GCC 版本, build-id 等)
 *
 * 即第一档 (离线静态分析) 完全挡死, 第二档 (running ptrace 攻击者)
 * 提高代价但挡不死, 第三档 (输出/外部) 不在保护范围.
 *
 * ─── 性能 ──────────────────────────────────────────────────────────────
 *
 * 每次 _OBF 调用 = 1 次 alloca + N 字节 XOR 循环.  典型字符串 N≈30,
 * 一次解码大约 10-30ns.  日志/错误路径完全不在乎.  不要在每秒百万
 * 次调用的 hot loop 里用 OBFSTR -- 那个场景下 alloca + 循环的开销
 * 会被放大.
 */

#ifndef ANTIREV_OBFSTR_H
#define ANTIREV_OBFSTR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

/* Per-position deobfuscation key.  KEEP IN SYNC with obf_key() in
 * tools/obfstr_gen.py — they encrypt and decrypt with the same formula,
 * so any change here must mirror there or every protected string will
 * decode to garbage.
 *
 * The formula is intentionally non-trivial enough that a casual reader
 * can't infer it from a single decoded byte, but cheap enough that the
 * decode loop stays in the noise on a release build. */
#define _OBF_K(i) ((uint8_t)(0x5a ^ (((((unsigned)(i)) * 7u) + 13u) & 0xffu)))

/* Decode `__VA_ARGS__` (a comma-separated list of encrypted bytes
 * produced by the codegen) back to a NUL-terminated string on the
 * caller's stack.  Yields a `const char *` that's valid until the
 * enclosing FUNCTION returns.
 *
 * Why __builtin_alloca instead of `char buf[N]`: GCC's lifetime rule
 * for variables declared inside a statement-expression `({...})` is
 * not consistently the enclosing function — depending on version the
 * storage may be released the moment the SE ends, after which a
 * subsequent SE can reuse the slot for *its* own encrypted byte
 * array.  Caller code that held the pointer (`p = OBFSTR("a"); ...
 * q = OBFSTR("b"); strcmp(p, "a")`) then reads the second call's
 * ciphertext through the first call's pointer — strcmp returns
 * non-zero, the test reports "second call yielded different bytes",
 * and from outside it looks like the decoder is broken.  alloca'd
 * memory survives the SE because it lives on the caller's frame, not
 * inside the SE block. */
#define _OBF(...)                                                         \
    ({                                                                    \
        const volatile uint8_t _antirev_obf_e[] = { __VA_ARGS__ };        \
        size_t _antirev_obf_n = sizeof(_antirev_obf_e);                   \
        char *_antirev_obf_buf =                                          \
            (char *)__builtin_alloca(_antirev_obf_n + 1);                 \
        for (size_t _antirev_obf_i = 0;                                   \
             _antirev_obf_i < _antirev_obf_n; _antirev_obf_i++)           \
            _antirev_obf_buf[_antirev_obf_i] =                            \
                (char)(_antirev_obf_e[_antirev_obf_i]                     \
                       ^ _OBF_K(_antirev_obf_i));                         \
        _antirev_obf_buf[_antirev_obf_n] = '\0';                          \
        (const char *)_antirev_obf_buf;                                   \
    })

/* OBFSTR is the bare marker — a function-style macro that the codegen
 * recognises and rewrites.  The fall-through definition (passthrough)
 * matters only when somebody compiles a single source file by hand
 * without running the codegen first; in that case the literal sits in
 * .rodata as it would have without obfuscation, the build still
 * compiles, and the output is functionally correct.  In the regular
 * CMake flow obfstr_gen.py replaces every OBFSTR("...") with _OBF(...)
 * before the preprocessor runs. */
#define OBFSTR(s) (s)

/* Convenience wrappers around the most common log / format / lookup
 * patterns in the antirev sources.  After codegen, the literal arg is
 * already an _OBF(...) call, so OBFSTR(fmt) further wraps it in the
 * passthrough macro and the expansion stays a `const char *`. */
#define LOG_ERR(fmt, ...) \
    fprintf(stderr, OBFSTR(fmt), ##__VA_ARGS__)

#define PERR(msg) \
    fprintf(stderr, OBFSTR("%s: %s\n"), OBFSTR(msg), strerror(errno))

#define OSNPRINTF(buf, n, fmt, ...) \
    snprintf(buf, n, OBFSTR(fmt), ##__VA_ARGS__)

#define ODLSYM(handle, name) \
    dlsym(handle, OBFSTR(name))

#endif /* ANTIREV_OBFSTR_H */
