# Anti-Rev 深度设计文档（基于 master 分支源码分析）

> 项目地址: https://github.com/sadelaifo/anti-rev  
> 分析时间: 2026-08-11  
> 分析分支: master（README 已严重滞后，本文档基于实际源码）

---

## 1. 项目概述

**Anti-Rev** 是一个企业级 Linux 二进制保护系统，用于加密可执行文件和共享库，在内存中解密执行，防止静态逆向工程。面向包含 **100+ 可执行文件、550+ 共享库、1000+ Python 脚本**的大型软件套件。

### 核心设计目标

| 目标 | 实现方式 |
|------|----------|
| **静态防护** | 磁盘上的二进制始终以 AES-256-GCM 密文存在 |
| **内存执行** | 运行时解密到 memfd（内存文件描述符），**不落盘** |
| **透明加载** | LD_PRELOAD shim + 守护进程，glibc 动态链接器无感知 |
| **跨进程共享** | 守护进程集中解密，通过 SCM_RIGHTS 传递 fd |
| **反指纹** | 环境变量重命名、per-build 随机前缀、字符串混淆、无 SONAME |

---

## 2. 系统架构

### 2.1 组件总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Anti-Rev 系统架构                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  OFFLINE 打包阶段                                                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  protect.py │    │antirev-pack │    │   build.py  │    │  miniyaml   │  │
│  │  (加密器)    │    │   .py       │    │(Python编译) │    │  (YAML解析) │  │
│  └──────┬──────┘    └──────┬──────┘    └─────────────┘    └─────────────┘  │
│         │                  │                                                │
│         ▼                  ▼                                                │
│  ┌─────────────────────────────────────────┐                                │
│  │         AES-256-GCM 加密打包             │                                │
│  │  your_binary + libfoo.so + libbar.so    │                                │
│  │         ↓ 加密 + 打包为 Bundle            │                                │
│  │  protected_binary (自包含 ELF)           │                                │
│  │  [stub ELF | bundle | trailer]           │                                │
│  └─────────────────────────────────────────┘                                │
│                     │                                                       │
│                     ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        RUNTIME 执行流程                              │   │
│  │                                                                     │   │
│  │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────────┐  │   │
│  │  │   stub   │───→│  memfd   │───→│ fexecve  │───→│ target binary │  │   │
│  │  │ (启动器)  │    │ (解密)   │    │ (执行)   │    │  (同PID运行)  │  │   │
│  │  └────┬─────┘    └──────────┘    └──────────┘    └──────┬───────┘  │   │
│  │       │                                                  │         │   │
│  │       │  LD_PRELOAD=/proc/self/fd/<antirev_shim.so>      │         │   │
│  │       └──────────────────────────────────────────────────┘         │   │
│  │                              │                                      │   │
│  │                              ▼                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │              antirev_shim.so (单一 LD_PRELOAD DSO)           │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │   │
│  │  │  │  exe_shim   │  │ dlopen_shim │  │ aarch64_extend_shim │  │   │   │
│  │  │  │ (身份隐藏)   │  │(dlopen拦截) │  │   (ARM扩展拦截)      │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │   │
│  │  │  │patch_fetch  │  │patch_redirect│  │   daemon_client    │  │   │   │
│  │  │  │ (.pat获取)   │  │(.pat重定向)  │  │   (守护进程客户端)   │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                              │                                      │   │
│  │                              ▼                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │                      lrxd (守护进程)                         │   │   │
│  │  │  - 扫描 $HOME/SA 目录中的加密 .so/.elf/.pat 文件             │   │   │
│  │  │  - 并行解密到 memfd，构建 DT_NEEDED 依赖图                   │   │   │
│  │  │  - 通过 SCM_RIGHTS 传递 fd 给客户端                          │   │   │
│  │  │  - 支持 OP_GET_CLOSURE 批量获取传递性依赖                    │   │   │
│  │  │  - 支持 OP_GET_PATCH 热补丁按需解密                          │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │              antirev_client.py (Python 集成)                 │   │   │
│  │  │  - 连接守护进程，拦截 ctypes.CDLL 和 sys.meta_path           │   │   │
│  │  │  - 透明加载加密 Python 扩展模块                              │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ALTERNATIVE: kmod2 内核模块架构（实验性）                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  antirevfs.ko — 堆叠只读内核文件系统                                  │   │
│  │  - 在 read_folio (页错误) 中 AES-GCM 解密                             │   │
│  │  - 内核页缓存自动提供跨进程页面共享                                   │   │
│  │  - 解密授权门控：exec 加载 vs 其他打开                                 │   │
│  │  - 无需 stub/shim/daemon/client，纯内核态                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 核心数据格式

### 3.1 受保护二进制文件格式（Bundle）

```
┌──────────────────────────────────────────────────────────────────────┐
│                         Protected Binary Layout                       │
├──────────────────────────────────────────────────────────────────────┤
│  [stub ELF]                     ← 编译好的启动器（~50KB stripped）    │
│  ─────────────────────────────────────────────────────────────────── │
│  [bundle]                       ← 加密包                              │
│    [bundle_flags: 1B]           ← bit0=HAS_MAIN, bit1=DAEMON_LIBS    │
│    ── if HAS_MAIN ──                                                 │
│    [name_len: 2B LE] [name: name_len]                                │
│    [iv: 12B] [tag: 16B] [ct_size: 8B LE] [ciphertext: ct_size]       │
│    ── if DAEMON_LIBS ──                                              │
│    [num_needed: 2B LE]                                               │
│    [name_len: 2B LE] [name: name_len] ... (DT_NEEDED 列表)            │
│  ─────────────────────────────────────────────────────────────────── │
│  [trailer: 48B]                 ← 文件末尾固定 48 字节                │
│    [bundle_offset: 8B LE]       ← bundle 在文件中的偏移               │
│    [part1: 32B]                 ← AES key share (NOT the real key!)   │
│    [magic: 8B] "ANTREV01"       ← 校验标记                            │
└──────────────────────────────────────────────────────────────────────┘
```

**关键变化**（与 README 描述不同）：
- Trailer 中的 32 字节 **不是 AES 密钥本身**，而是 `part1` —— 一个密钥分片
- 真实密钥需要通过 **Keysplit 派生**（见第 5 节）
- Bundle 增加了 `bundle_flags` 和 needed-libs section，支持 lazy 加载模式

### 3.2 独立加密文件格式（.so / .elf / .pat）

```
[magic: 8B "ANTREV01"] [iv: 12B] [tag: 16B] [ciphertext: ...]
```

### 3.3 守护进程协议 v2

**消息格式**: `[u32 op] [u32 payload_len] [payload...]` + 可选 SCM_RIGHTS

| 操作码 | 方向 | 说明 |
|--------|------|------|
| `OP_INIT (0x01)` | C→D | 客户端初始化，可选过滤列表 |
| `OP_GET_LIB (0x02)` | C→D | 请求单个库 |
| `OP_BYE (0x03)` | C→D | 断开连接 |
| `OP_LIST (0x04)` | C→D | 列出所有库名（无 fd） |
| `OP_GET_CLOSURE (0x05)` | C→D | 请求库及其传递性加密依赖 |
| `OP_GET_PATCH (0x06)` | C→D | 按需解密 .pat 热补丁文件 |
| `OP_BATCH (0x81)` | D→C | 批量回复（含 fd） |
| `OP_END (0x82)` | D→C | 批量结束标记 |
| `OP_LIB (0x83)` | D→C | 单库回复（含 fd） |
| `OP_NAMES (0x84)` | D→C | 批量名称列表（无 fd） |

---

## 4. 密钥管理（Keysplit）

### 4.1 派生公式

```
real_key = SHA256( part1 || SHA256(lrxd_file) || version_field )
```

| 组件 | 来源 | 说明 |
|------|------|------|
| **part1** | 32 字节，嵌入在每个受保护二进制文件的 trailer 中 | 明文存在，但单独无法解密 |
| **part2** | `SHA256(lrxd)` — 守护进程可执行文件的完整哈希 | 绑定到部署环境的 lrxd 完整性 |
| **version_field** | 从 `$HOME/SA/version` 脚本输出解析 | 绑定到部署版本 |

### 4.2 版本字段解析（双格式）

```python
# 与 stub.c ksv_parse / protect.py parse_version_field 完全一致
if b"." in stdout:
    # 测试构建（含点版本）：取第一个 "." 之后的全部内容
    field = stdout[stdout.index(b".") + 1:].strip()
else:
    # 正式构建（DY 标记版本）：取 "Version: DY" 之后、"SPC" 之前
    start = stdout.index(b"Version: DY") + len(b"Version: DY")
    line = stdout[start: newline_or_eof]
    spc = line.find(b"SPC")
    if spc >= 0: line = line[:spc]
    field = line.strip()
```

**安全性**: 即使攻击者提取了 part1，没有目标机器上的 `lrxd` 和正确的版本值也无法派生真实密钥。热补丁文件 (`.pat`) 使用相同的 keysplit 派生密钥加密。

---

## 5. Stub 启动器（stub.c）

### 5.1 启动流程

```
main()
├── init_log_gate()              ← 诊断日志门控（ANTIREV_LOG，默认 OFF）
├── dump_initial_state()         ← 记录 argv/envp/fd 初始状态
│
├── 1. readlink("/proc/self/exe") → real_exe  ← 原始路径（绕过 LD_PRELOAD）
├── 2. open("/proc/self/exe") → 读取 48B trailer
│   ├── bundle_offset (8B)
│   ├── part1 (32B)              ← 密钥分片
│   └── magic "ANTREV01" (8B)
│
├── 3. derive_real_key(part1)    ← Keysplit 派生真实 AES 密钥
│   ├── open($HOME/SA/bin/sa/lrxd) → SHA256 → part2
│   ├── fork+exec($HOME/SA/version) → 解析 stdout → version_field
│   └── SHA256(part1 || part2 || version_field) → real_key
│
├── Phase 1: scan bundle headers  ← 仅读取元数据，密文不加载到 RAM
│   ├── bundle_flags (1B)
│   ├── if HAS_MAIN: 读取 main entry (name, iv, tag, ct_size, ct_offset)
│   └── if DAEMON_LIBS: 读取 needed-libs section (DT_NEEDED 列表)
│
├── Phase 2: single-pass decrypt  ← GHASH + CTR 同时（单次 I/O）
│   ├── make_memfd()             ← 随机命名，无 CLOEXEC
│   ├── aes256gcm_init(key, iv)
│   ├── loop: pread(ct) → aes256gcm_onepass() → write(memfd)
│   └── aes256gcm_ghash_verify(tag) → 失败则 ftruncate(0) 擦除
│
├── Mode A: 无 main → run_daemon_forever()
│   └── 守护进程模式（见 5.2）
│
├── Mode B: 有 main → Client 模式
│   ├── Phase 3: fetch_libs_from_daemon()
│   │   ├── make_sock_addr(key) → 抽象 Unix socket 名
│   │   ├── retry 50 次 connect → 失败则 spawn_local_daemon()
│   │   ├── OP_LIST → 获取全部加密库名
│   │   ├── if has_needed_section:
│   │   │   ├── intersect_needed_encrypted() → 仅获取 DT_NEEDED 中的加密库
│   │   │   └── keep socket open for lazy mode
│   │   └── else: OP_INIT → 获取全部库（backward compat）
│   │
│   ├── explicit_bzero(key)      ← 擦除密钥
│   │
│   ├── Phase 4: write embedded shim blob to memfd
│   │   └── antirev_shim_blob (编译时烘焙进 stub)
│   │
│   ├── Phase 4b: split libs
│   │   ├── DT_NEEDED libs → symlink dir (保留原始符号查找顺序)
│   │   └── 其余 libs → __r_FM (按需 dlopen)
│   │
│   ├── Phase 4c: create symlink dir
│   │   └── /tmp/<random_prefix>_<pid>_XXXXXX/libfoo.so → /proc/self/fd/N
│   │
│   ├── Phase 5: build_exec_env()
│   │   ├── __r_RE=real_exe
│   │   ├── __r_MF=main_fd
│   │   ├── LD_PRELOAD=/proc/self/fd/<shim_fd>
│   │   ├── __r_FM=name=fd,... (非 DT_NEEDED 库)
│   │   ├── LD_LIBRARY_PATH=<symlink_dir>
│   │   ├── __r_CF=fd1,fd2,... (待关闭的 DT_NEEDED fds)
│   │   ├── __r_LS=<daemon_socket> (lazy 模式)
│   │   ├── __r_EL=lib1,lib2,... (全部加密库名)
│   │   ├── __r_SD=<symlink_dir>
│   │   └── __r_NP=1 (黑名单 exe 的 escape hatch)
│   │
│   └── Phase 6: exec_target()
│       ├── if native arch: fexecve(main_fd, argv, new_env)
│       ├── if ENOSYS (qemu-user): fallback to qemu-aarch64-static
│       └── __r_FX=1 强制显式 QEMU 分发（保留 argv[0]）
```

### 5.2 守护进程模式（run_daemon_forever）

```
run_daemon_forever()
├── raise_fd_limit()             ← 提升 NOFILE 到 hard cap
├── sweep_dead_symlink_dirs()    ← 清理崩溃遗留的 /tmp 符号链接目录
├── decrypt_own_libs()
│   ├── scan_encrypted_libs()
│   │   ├── collect_enc_paths()  ← 递归扫描 $HOME/SA，收集 .so/.elf
│   │   ├── parallel decrypt     ← pthread 工作窃取池
│   │   ├── arch filter          ← 按 e_machine 过滤（支持多架构共存）
│   │   └── basename dedup       ← 去重同名库
│   └── build_and_log_deps_graph()
│       ├── parse_dt_needed()    ← mmap 每个库，解析 PT_DYNAMIC
│       ├── build_deps_graph()   ← 构建邻接表
│       └── dump_deps_graph_log() ← 调试日志
│
├── daemon_open_listen_socket()
│   └── 抽象 Unix socket: sun_path = hex(AES_K(0^128)[0:8])
│       ← 16 位十六进制，无 "antirev_" 前缀（反指纹）
│
├── fork() → parent _exit(0)
├── child: setsid(), close stdio
├── signal(SIGPIPE, SIG_IGN)
├── pthread_sigmask(SIG_BLOCK, SIGTERM/INT/HUP/QUIT)
├── eventfd() → shutdown 信号
├── pthread_create(worker) → daemon_serve()
│   └── epoll 单线程服务循环
│       ├── EPOLLIN on listen_fd → accept4 + SO_PEERCRED uid 校验
│       ├── EPOLLIN on client → daemon_handle_request()
│       │   ├── OP_INIT → send_init_batch()
│       │   ├── OP_GET_LIB → handle_get_lib()
│       │   ├── OP_LIST → handle_list()
│       │   ├── OP_GET_CLOSURE → handle_get_closure() + DFS 拓扑排序
│       │   └── OP_GET_PATCH → handle_get_patch()
│       │       ├── reload_part1_from_trailer()
│       │       ├── derive_real_key()  ← 重新派生（per-request，最小化密钥驻留）
│       │       └── decrypt_enc_file() → memfd → SCM_RIGHTS
│       └── EPOLL on shutdown_efd → 退出
│
└── sigwait() → write(eventfd) → pthread_join → cleanup → _exit(0)
```

---

## 6. antirev_shim.so（单一 LD_PRELOAD DSO）

### 6.1 架构演进

**重大变化**: 所有 shim 合并为 **单一的 `antirev_shim.so`**（每个架构一个），不再是多个独立 DSO。这减少了 memfd 数量和 LD_PRELOAD 条目。

| 源文件 | 功能 | 架构 |
|--------|------|------|
| `exe_shim.c` | `readlink`/`readlinkat`/`realpath`/`getauxval`/`prctl` 身份隐藏 | 全部 |
| `dlopen_shim.c` | `dlopen()` 重定向，支持 eager 和 lazy 两种模式 | 全部 |
| `aarch64_extend_shim.c` | `ANTI_LoadProcess` 劫持、`open`/`openat` .elf 重定向、`popen`/`pclose` | aarch64 独有 |
| `daemon_client.c` | 守护进程协议客户端（共享 socket、fd 映射、加密名集合） | 全部 |
| `patch_fetch.c` | `.pat` 后缀检查 + `OP_GET_PATCH` 获取（5 秒 recv 超时） | 全部 |
| `patch_redirect.c` | `fopen`/`fopen64` .pat 重定向；x86 上额外 `open`/`openat` .pat | 全部 |

### 6.2 exe_shim（身份隐藏）

**核心问题**: 目标二进制通过 memfd 执行，`/proc/self/exe` 指向 `"memfd:<name> (deleted)"`，导致依赖 exe 路径查找配置文件、socket、资源的代码失败。

**拦截点**:

| 函数 | 拦截逻辑 |
|------|----------|
| `readlink`/`readlinkat` | `path == "/proc/self/exe"` → 返回 `__r_RE` |
| `__readlink_chk`/`__readlinkat_chk` | Fortified 变体 |
| `realpath`/`canonicalize_file_name` | 同上 |
| `__realpath_chk` | Fortified 变体 |
| `getauxval(AT_EXECFN)` | 返回 `__r_RE` |
| `prctl(PR_SET_NAME)` | Constructor 中恢复原始进程名 |
| `program_invocation_name` | 指向 `__r_RE` |

**Owner 检测**（关键安全边界）:
```c
// 主检测：/proc/self/exe 包含 "memfd:"
// QEMU 回退：__r_MF 环境变量存在
// 共享回退：daemon_client_is_owner()（exe_shim ctor 设置的标志）
```

**子进程处理**: 非 owner 子进程（如 `popen`、`fork+exec`）自动清理 antirev 环境变量，防止泄露。

### 6.3 dlopen_shim（库加载拦截）

**两种模式**:

#### Eager 模式（legacy）
- `__r_FM="libfoo.so=6,libbar.so=7"`
- stub 预取所有库，dlopen 仅做路径重定向

#### Lazy 模式（新默认）
- `__r_LS` = 守护进程 socket fd（保持连接）
- `__r_EL` = 全部加密库名集合
- `__r_SD` = 符号链接目录

**Lazy 加载流程**:
```
dlopen("libfoo.so")
├── basename match against __r_EL
├── if not encrypted → passthrough to real_dlopen
├── if encrypted:
│   ├── pthread_mutex_lock(&g_lock)
│   ├── fetch_closure("libfoo.so")
│   │   ├── send OP_GET_CLOSURE("libfoo.so")
│   │   ├── recv OP_BATCH(es) until OP_END
│   │   ├── for each (name, fd):
│   │   │   ├── if cached → close fresh fd
│   │   │   └── else: create symlink in __r_SD, cache (name, fd)
│   │   └── return topological-ordered new names
│   ├── preload_closure_deps()
│   │   └── for each new dep (except root):
│   │       └── real_dlopen(symlink_path, RTLD_LAZY | RTLD_GLOBAL)
│   │           ← 预加载使 glibc 链接映射中已存在，避免 DT_RPATH 回退到磁盘密文
│   └── pthread_mutex_unlock(&g_lock)
└── real_dlopen(__r_SD/libfoo.so, flags)
```

**Escape hatch**: `__r_NP=1` 禁用 per-dep preload 循环，使用 plaintext-equivalent 加载语义（解决隐式跨库符号依赖问题）。

### 6.4 aarch64_extend_shim（ARM 特有）

#### ANTI_LoadProcess 劫持

```c
struct ANTI_ProcessInfo {
    const char *pgName;   // offset 0
    const char *ltrBin;   // offset 8 ← 重写此路径
    // ... rest opaque
};
```

- 将 `info->ltrBin` 从磁盘密文路径重写为 `/proc/self/fd/N`（memfd）
- **持久化重写**：不恢复，因为业务 loader 可能在返回后延迟读取路径

#### open/openat .elf 重定向（-Bsymbolic 回退）

当业务 .so 使用 `-Bsymbolic` 或 `dlsym(handle, ...)` 时，LD_PRELOAD 无法拦截 `ANTI_LoadProcess` 符号。回退到 libc 文件 IO 层拦截：

```
openat(dirfd, pathname)
├── if basename ends with ".elf" AND in __r_EL or __r_FM
├── AND owner process
├── AND not already /proc/self/fd/
└── → resolve_path(basename) → /proc/self/fd/N
```

**使用 raw syscall**（非 dlsym）: glibc >= 2.33 的 `newfstatat`/`stat`/`lstat` 是内联函数，无导出符号。使用 `syscall(__NR_openat)` 等避免 ENOSYS。

#### popen/pclose 替换

**问题**: glibc 的 `popen` 在 aarch64 上使用 `vfork(CLONE_VM|CLONE_VFORK)`，在 memfd 密集、LD_PRELOAD 活跃、ARM Crypto Extensions 使用的进程中会损坏父进程状态。

**解决方案**: 纯 `fork+exec` 实现：
```c
popen(command, "r")
├── pipe()
├── fork()
│   └── child: dup2(pipe[1], STDOUT), scrub ANTIREV_* env, execl("/bin/sh", ...)
├── fdopen(pipe[0], "r")
└── track (FILE* → pid) in g_popen_table
```

---

## 7. 热补丁支持（Hot-Patch）

### 7.1 架构

热补丁功能**内置于 antirev_shim** 中，无需单独的 lrxd.so 或发现文件。

```
业务代码打开 .pat 文件
├── fopen/fopen64 → patch_redirect.c 拦截
│   └── if .pat suffix AND read-only mode AND owner
│       └── patch_fetch_fd(pathname) → OP_GET_PATCH → memfd → fdopen()
│
├── open/openat (x86) → patch_redirect.c 拦截
│   └── 同上
│
└── open/openat (aarch64) → aarch64_extend_shim.c 拦截
    └── 同上
```

### 7.2 守护进程端（handle_get_patch）

```
OP_GET_PATCH("foo.pat")
├── basename 校验（拒绝含 '/' 的路径，防遍历）
├── find_under_dir(scan_dir, "foo.pat")  ← 递归搜索 $HOME/SA
├── reload_part1_from_trailer()          ← 从自身体 trailer 重新读取 part1
├── derive_real_key(part1)               ← 重新派生密钥（per-request）
├── decrypt_enc_file(path, key)          ← 解密到 memfd
└── SCM_RIGHTS 传递 fd
```

**安全设计**: 每个 .pat 请求独立重新派生密钥，密钥不在守护进程中长期驻留。

---

## 8. 加密实现（crypto.c）

### 8.1 AES-256-GCM

纯 C 实现，**不依赖外部加密库**:

```c
typedef struct {
    uint8_t rk[240];      // AES-256 round keys
    uint8_t H[16];        // GHASH subkey = AES_K(0^128)
    uint8_t J0[16];       // initial counter = IV || 0x00000001
    uint8_t ghash[16];    // running GHASH accumulator
    size_t  ghash_bytes;  // total ciphertext bytes fed
    uint8_t ghash_buf[16];// buffered incomplete block
    size_t  ghash_buf_len;
    uint8_t ctr[16];      // next counter block
    uint8_t ks[16];       // buffered keystream block
    size_t  ks_used;      // bytes consumed from ks
} aes256gcm_ctx;
```

**API**:
- `aes256gcm_init()` — 初始化/重置上下文
- `aes256gcm_ghash_update()` — Pass 1: 累积 GHASH
- `aes256gcm_ghash_verify()` — 验证 tag
- `aes256gcm_ctr_decrypt()` — Pass 2: CTR 解密
- `aes256gcm_onepass()` — **单次 I/O**: GHASH + CTR 同时（stub 主路径使用）

### 8.2 SHA-256

FIPS 180-4 纯 C 实现，用于 keysplit 派生。

---

## 9. 反指纹与混淆技术

### 9.1 环境变量重命名

| 旧名 | 新名 | 说明 |
|------|------|------|
| `ANTIREV_REAL_EXE` | `__r_RE` | 真实 exe 路径 |
| `ANTIREV_MAIN_FD` | `__r_MF` | 主程序 memfd |
| `ANTIREV_FD_MAP` | `__r_FM` | fd 映射 |
| `ANTIREV_CLOSE_FDS` | `__r_CF` | 待关闭 fds |
| `ANTIREV_LIBD_SOCK` | `__r_LS` | 守护进程 socket |
| `ANTIREV_ENC_LIBS` | `__r_EL` | 加密库名集合 |
| `ANTIREV_SYMLINK_DIR` | `__r_SD` | 符号链接目录 |
| `ANTIREV_NO_PRELOAD` | `__r_NP` | 禁用预加载循环 |

### 9.2 编译时字符串混淆（obfstr）

- `tools/obfstr_gen.py` 在构建时重写源代码
- 所有字符串字面量转换为 `_OBF(...)` 宏调用
- 运行时通过 `__builtin_alloca` 在栈上解码，函数返回后自动释放
- **数组初始化器不被转换**（如 `static const char *arr[] = {"foo", NULL}`），所以敏感字符串必须通过局部变量 + OBFSTR 构建

### 9.3 Per-Build 随机 /tmp 前缀

- CMake 配置时生成 8 位随机十六进制前缀（如 `.a3f7b2c1_`）
- 符号链接目录: `/tmp/.a3f7b2c1_<pid>_XXXXXX`
- 避免通过 `ls /tmp/` 指纹化 antirev

### 9.4 守护进程命名

- 守护进程二进制: `lrxd-x86_64` / `lrxd-aarch64`（无 "antirev" 前缀）
- 抽象 socket 名: 16 位十六进制（`AES_K(0^128)[0:8]` 的 hex），无 "antirev_" 前缀
- shim DSO: `NO_SONAME TRUE`，避免 `strings stub` 泄露 shim 名称

---

## 10. 构建系统

### 11.1 CMake 配置

```cmake
# 原生构建（不支持交叉编译）
if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(TARGET_ARCH "aarch64")
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(TARGET_ARCH "x86_64")
endif()

# Per-build 随机 /tmp 前缀
string(RANDOM LENGTH 8 ALPHABET "0123456789abcdef" _antirev_rand_hex)
set(ANTIREV_TMP_PREFIX ".${_antirev_rand_hex}_")

# obfstr 代码生成
obfstr_codegen_sources(STUB_SOURCES_OBF stub/stub.c stub/crypto.c ...)

# 二进制 blob 头生成（shim .so → C 数组）
make_blob_header(antirev_shim_blob.h antirev_shim.so "antirev_shim_blob" antirev_shim)
```

### 11.2 构建产物

| 产物 | 说明 |
|------|------|
| `stub` / `stub_aarch64` | 启动器可执行文件 |
| `antirev_shim_x86_64.so` / `antirev_shim_aarch64.so` | 单一 LD_PRELOAD shim |
| `antirev_shim_blob.h` / `antirev_shim_blob_aarch64.h` | 烘焙进 stub 的 shim 字节数组 |

---

## 11. 已知问题与工程权衡

### 12.1 隐式符号依赖与 `__r_NP`

业务库的构造函数可能引用由兄弟库提供的符号（无 `DT_NEEDED` 边）。per-dep preload 循环在隔离状态下运行每个 ctor，导致懒绑定失败。

**解决方案**: `__r_NP=1` 禁用 preload 循环，让 glibc 的递归 `DT_NEEDED` 遍历一次性加载整个依赖树（与 plaintext 等价）。代价：失去 `DT_RPATH` 回退保护。

### 12.2 路径去重与 `/proc/self/fd/N`

glibc 基于路径的 `l_name` 去重。`/proc/self/fd/6` 与磁盘路径被视为不同库，可能导致同一库被加载两次。

**缓解**: 通过 symlink dir 提供稳定路径，dlopen_shim 缓存 fd 避免复用。

### 12.3 调试符号文件

`exe_shim` 伪造 `readlink("/proc/self/exe")` 指向磁盘上的加密 stub。业务软件相对于 exe 路径扫描 `.debug` 文件的行为受影响。

**解决方案**: 始终部署 `.debug` 文件到 stub 同级目录。

### 12.4 QEMU-user 兼容性

- `fexecve` 在 qemu-user 下 `ENOSYS`
- `__r_FX=1` 强制显式 QEMU 分发，保留真实 `argv[0]`
- aarch64 owner 检测有 QEMU 特殊路径（`__r_MF` 回退）

### 12.5 峰值 fd 消耗

每个解密的库持有一个打开的 memfd。大型部署（550+ 库）可能需要提高 `ulimit -n`。

---

## 12. 文件清单（关键文件）

```
anti-rev/
├── CMakeLists.txt              # 主构建配置
├── cmake/
│   ├── bin2h.py                # 二进制 → C 数组头
│   ├── runtime_paths.c.in      # per-build 随机前缀模板
│   └── tests.cmake             # 测试定义
├── encryptor/
│   ├── protect.py              # 核心加密工具（~24KB）
│   ├── antirev-pack.py         # YAML 驱动批量打包（~47KB）
│   ├── build.py                # Python 编译/混淆（~38KB）
│   └── miniyaml.py             # 内置 YAML 子集解析器（~7KB）
├── stub/
│   ├── stub.c                  # 核心启动器（~134KB）
│   ├── crypto.c / crypto.h     # AES-256-GCM + SHA-256 纯 C 实现
│   ├── exe_shim.c              # 身份隐藏 shim（~22KB）
│   ├── dlopen_shim.c           # dlopen 拦截（~16KB）
│   ├── aarch64_extend_shim.c   # ARM 扩展（~30KB）
│   ├── daemon_client.c / .h    # 守护进程客户端（~9KB）
│   ├── patch_fetch.c / .h      # 热补丁获取（~4KB）
│   ├── patch_redirect.c        # 热补丁重定向（~10KB）
│   ├── keysplit_version.h      # 版本字段解析（~4KB）
│   ├── obfstr.h                # 字符串混淆宏（~13KB）
│   └── runtime_paths.h         # 运行时路径（~2KB）
├── kmod2/
│   ├── DESIGN.md               # kmod2 设计文档
│   └── module/
│       ├── super.c             # 文件系统注册、mount、key 获取
│       ├── inode.c             # inode 查找
│       ├── file.c              # read_folio 解密、open 门控
│       ├── crypto.c            # 内核 crypto API
│       ├── gate.c              # 解密授权门控
│       └── antirevfs.h
├── tools/
│   ├── obfstr_gen.py           # 编译时字符串混淆代码生成
│   ├── antirev_client.py       # Python 守护进程客户端
│   ├── depgraph.py             # 依赖图可视化
│   └── missing_syms.py         # 重复符号检测
└── tests/                      # 测试套件
```

---

## 13. 环境变量完整参考

### 14.1 运行时环境变量（stub → shim 传递）

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `__r_RE` | 受保护 exe 的真实磁盘路径 | — |
| `__r_MF` | 主程序 memfd fd | — |
| `__r_FM` | Eager fd 映射 `libfoo.so=6,libbar.so=7` | — |
| `__r_CF` | DT_NEEDED fds 关闭列表 | — |
| `__r_LS` | 守护进程 Unix socket fd | — |
| `__r_EL` | 全部加密库 basename 集合 | — |
| `__r_SD` | 符号链接目录路径 | — |
| `__r_NP` | 禁用 per-dep preload 循环 | — |
| `__r_FX` | 强制显式 QEMU 分发 | — |

### 14.2 用户可调环境变量

| 变量 | 说明 |
|------|------|
| `ANTIREV_LOG` | stub 诊断日志开关（默认 OFF） |
| `ANTIREV_LOG_FILE` | stub 日志路径（默认 `/tmp/antirev_stub.log`） |
| `ANTIREV_DLOPEN_LOG` | dlopen_shim 决策日志路径 |
| `ANTIREV_AARCH64_EXTEND_LOG` | aarch64_extend_shim 日志路径 |
| `ANTIREV_PATCH_LOG` | 热补丁决策日志路径 |
| `ANTIREV_LD_DEBUG` | 注入 `LD_DEBUG` 到受保护进程 |
| `ANTIREV_TMP_PREFIX` | 覆盖 per-build 随机 /tmp 前缀 |

---

*本文档基于 anti-rev 项目 master 分支的实际源码分析生成，修正了 README 中大量过时的信息（如密钥管理、Bundle 格式、shim 架构、环境变量命名等）。*
