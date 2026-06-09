# antirev 在 QEMU 模式下的工作原理

## 背景：什么是 "QEMU 模式"

这里指 **qemu-user（用户态翻译，binfmt_misc）** 场景：在 x86_64 宿主机上运行 aarch64
的客户机二进制。生产部署即为此形态（目标环境 aarch64 / glibc 2.34，运行于 x86 宿主的
qemu 容器中）。

qemu-user 与原生执行的根本区别，导致 antirev 多处原生假设失效：

| 原生假设 | qemu-user 下的实际情况 |
|---|---|
| `/proc/self/exe` → `memfd:<hex> (deleted)` | → **qemu 翻译器自身的二进制**（host 的 `qemu-aarch64-static`，x86_64 ELF） |
| `fexecve(memfd)` 走 `execveat(AT_EMPTY_PATH)` | qemu **不实现** `execveat` / `fexecve` → **ENOSYS** |
| `open("/proc/self/exe")` 读到 guest 二进制 | qemu 可能不重定向，读到 host 的 qemu x86 ELF |

antirev 的 QEMU 适配就是逐个修补这些断裂点。整条链路如下。

---

## 1. stub 启动：跨架构 exec（`stub.c` Phase 6）

核心是 `exec_target()`（`stub/stub.c:2565`）。memfd 解密完成后，它决定如何把控制权交给
客户机程序：

1. **`needs_qemu_for_fd(main_fd)`**（`stub.c:2497`）：读 ELF 头的 `e_machine`，与编译期
   宿主 arch 比较。不一致 → 需要 QEMU。
2. **路径 A：架构匹配**（如真 aarch64 硬件）→ 直接 `fexecve(main_fd)`。
3. **路径 B：fexecve 返回了**（说明失败）→ 检查 `errno`：
   - **`ENOSYS`**：这正是 qemu-user 把 native-arch 客户机跑在 qemu 里时的特征——
     `execveat` 未实现。**fall through 到显式 QEMU 派发**。
   - 其他 errno：真正的本地执行失败，return 让 `main()` 报错。
4. **显式 QEMU 派发**：
   - `build_qemu_argv()`（`stub.c:2526`）构造
     `[binname, "-0", binname, /proc/self/fd/N, <原始 args>]`。`-0 binname` 让 qemu 把
     **guest 的 argv[0] 设成真实程序名**，否则按名字分发 / 找资源的业务程序会看到
     `/proc/self/fd/N`。
   - `try_exec_known_qemu()`（`stub.c:2549`）依次 `stat` + `execve` 这些路径：
     `/usr/bin/qemu-aarch64-static`、`/usr/bin/qemu-aarch64`。注意这里用
     `qemu /proc/self/fd/N` 运行，走 qemu 的核心解释路径，绕开 `execveat`、不触发 binfmt
     二次递归。
5. **最后兜底**：再裸 `fexecve` 一次。

**反逆向细节**：QEMU 路径名都用 `OBFSTR()` 加密存放（`-0` 本身除外），避免 `strings`
直接打印出 "这个 stub 会从 QEMU 启动" 的指纹。

---

## 2. shim 的 owner 识别：QEMU 下 `/proc/self/exe` 不再可信

shim（LD_PRELOAD 注入）需要区分 "我是被保护的主进程（owner）" 还是 "继承了 LD_PRELOAD
的普通子进程"。原生靠 `/proc/self/exe` 含 `memfd:` 判断。**QEMU 下这个 link 指向 qemu
翻译器，永远不含 `memfd:`**，于是引入 `__r_MF` 作为替代信号：

- **stub 注入**：`__r_MF=<main_fd>`（`stub.c:2142`），**只注入给直接 fexecve / qemu 的
  目标，从不传给子进程**——这是信任它的前提。
- **`detect_owner()`（`exe_shim.c:227`）** 三级判定：
  1. `/proc/self/exe` 含 `memfd:` → owner（原生路径）。
  2. 否则看 `__r_MF`，读 `/proc/self/fd/<N>` 的 link 是否含 `memfd:`。
  3. **QEMU 下连 fd link 都可能 readlink 失败 → 只要 `__r_MF` 存在就信任**
     （`exe_shim.c:248-250`）。
- 判定后 `daemon_client_mark_owner()` 把结论**存进共享的 daemon_client 状态**，然后
  `unsetenv("__r_MF")` 消费掉，防止 fork+exec 的子进程误判为 owner。

### 三个 shim 的协作（顺序很关键）

- **`exe_shim` 的 `is_owner_process()`（`exe_shim.c:78`）**：aarch64 分支加了 "qemu-only
  懒检测"。pre-ctor 调用（来自 DT_NEEDED 库的 C++ 静态构造器，如
  `boost::dll::program_location`）若直接 pass-through，会撞上 qemu 合成的失效
  `/proc/self/fd/N` 而 ENOENT 崩溃。解决：探测 `/proc/self/exe`——含 `memfd:` = 真 ARM
  硬件，保持老行为返回 0；**不含 = 在 qemu 下，用 `__r_MF` 当 owner 信号**（非破坏性读取，
  让 ctor 仍能消费）。
- **`aarch64_extend_shim` 的 ctor（`aarch64_extend_shim.c:244`）**：它在 exe_shim ctor
  **之后**运行，此时 `__r_MF` 已被 unsetenv。所以它的 owner 判定最终 fall back 到
  `daemon_client_is_owner()`——读 exe_shim 早先 stash 的共享结论
  （`aarch64_extend_shim.c:272`）。

---

## 3. daemon（lrxd）在 QEMU 下的 arch 自检

`lrxd` 守护进程要按客户机 arch 过滤要服务的库（install tree 里 x86 和 aarch64 同名库
共存）。原来用 `/proc/self/exe` 读 `e_machine`，**但 qemu 不一定重定向
`open("/proc/self/exe")`**——aarch64 的 lrxd 跑在 qemu 里会读到 host 的
`qemu-aarch64-static`（x86 ELF），误判自己是 x86，把整棵树的 aarch64 库全部 drop 掉，
客户端 ld.so 报库缺失。

修复（`stub.c:1474` 的 `g_my_machine`）：**直接用编译期 arch 常量**（aarch64 → `0xB7`），
不读 `/proc/self/exe`。daemon 二进制为特定 arch 编译，只能被该 arch 的进程加载，所以
编译期 arch 就是权威值。`/proc/self/exe` 仅作为编译期 arch 未知时的兜底
（`stub.c:1486` `detect_my_machine`）。

---

## 4. popen / system 的 vfork 问题

在 aarch64（含 qemu）下，glibc 基于 vfork 的 `popen` 会**破坏 memfd 密集的父进程**。
`aarch64_extend_shim` 用 plain fork+exec 重写 `popen` / `pclose`，自维护 `FILE*→pid` 表。
这条对 qemu 部署同样关键。

---

## 总结：QEMU 模式的本质

antirev 在 QEMU 下能工作，靠的是把**所有 "靠 `/proc/self/exe` 判身份" 的地方都加了
fallback**，并改用显式 `qemu /proc/self/fd/N` 运行解密后的 memfd：

```
stub: 解密 → memfd → needs_qemu? → execve(qemu, [-0 名, /proc/self/fd/N, args])
                                 ↘ fexecve ENOSYS → 同上兜底
  ↓ 注入 __r_MF（仅主进程）
shim owner 识别: memfd? ✗(qemu) → __r_MF? ✓ → 标记共享状态
  ↓
exe_shim 懒检测（boost::dll 等 pre-ctor 崩溃修复）
aarch64_extend_shim 读共享 owner 结论
daemon: 编译期 arch 常量（不读 /proc/self/exe）
```

### 关键代码索引

| 功能 | 位置 |
|---|---|
| 跨架构 exec 派发 | `stub/stub.c:2565` `exec_target` |
| 是否需要 QEMU（e_machine 比较） | `stub/stub.c:2497` `needs_qemu_for_fd` |
| 构造 qemu argv（`-0` 改写 argv[0]） | `stub/stub.c:2526` `build_qemu_argv` |
| 已知 QEMU 路径探测（OBFSTR） | `stub/stub.c:2549` `try_exec_known_qemu` |
| `__r_MF` 注入（仅主进程） | `stub/stub.c:2142` |
| daemon 编译期 arch 自检 | `stub/stub.c:1474` `g_my_machine` |
| owner 三级判定 + 共享 stash | `stub/exe_shim.c:227` `detect_owner` |
| aarch64 qemu-only 懒检测 | `stub/exe_shim.c:78` `is_owner_process` |
| extend_shim 读共享 owner 结论 | `stub/aarch64_extend_shim.c:272` |

### 端到端测试

`tests/arm64_qemu_demo/` 在 qemu-user 下覆盖完整流程：memfd + fexecve、dlopen 加密库、
popen 替换、Python 客户端。CMake 中 `ARM64 test via QEMU binfmt`
（`CMakeLists.txt:328`）通过 `QEMU_LD_PREFIX=/usr/aarch64-linux-gnu` 驱动。
