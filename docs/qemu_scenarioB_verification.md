# 场景 B(x86 stub + QEMU 拉起 aarch64)验证 —— 交接文档

> 状态:**验证准备中,等 WSL 安装 + 重启后继续**
> 分支:`xcc_qemu`(从 master `b679d0f` 切出)
> 目的:在本地 WSL+qemu(+docker)环境实测 antirev 的"场景 B"是否真的 work —— 之前为 Docker 写的适配,用户不确定有没有验过。

---

## 0. 一句话目标

验证 **场景 B**:**x86 native 的 stub**,检测到要拉起的是 **aarch64 业务二进制**,通过 **QEMU user-mode** 把它跑起来。重点验 `stub/stub.c` 里 `exec_target` 那套 dispatcher 在真实 QEMU+Docker 下到底成不成。

---

## 1. 两个场景的区分(关键背景)

`exec_target`(stub.c:2586)第一行靠 `needs_qemu_for_fd`(stub.c:2458)分叉,而它比较的是 **ELF e_machine vs stub 自己的编译架构**:

| 场景 | stub 架构 | `needs_qemu_for_fd` | 走 dispatcher? |
|---|---|---|---|
| **A 全 aarch64 模拟容器** | aarch64(在 QEMU 下跑) | 0(aarch64 看 aarch64) | **否** —— 直接 fexecve,靠 host binfmt |
| **B x86 stub + aarch64 target** | x86 native | 1 | **是** —— 走 QEMU dispatcher |

**用户明确要的是场景 B。** 那套精心写的 Docker 适配(`cache_qemu_from_probe` 等)正是为场景 B 写的。

---

## 2. 代码审视已发现的两个 bug(M1 要验掉)

**Bug 1 — `argv[0]` 丢失**(`build_qemu_argv`,stub.c:2477)

```c
out[0] = binname;        // 这成了 QEMU 自己的 argv[0](被忽略)
out[1] = fd_path;        // /proc/self/fd/N = guest 程序
// 原 argv[1..] 接后面
```

`execve(qemu, [binname, "/proc/self/fd/N", ...])` → guest 看到的 **argv[0] 变成 `/proc/self/fd/N`**,不是真实程序名。没用 QEMU 的 `-0 <argv0>` 选项。对 argv[0] 敏感的业务(按名找资源、multi-call 二进制)会出错。
**修法**:用 `qemu -0 <binname> /proc/self/fd/N <args>`,即把 binname 作为 `-0` 的值,而不是放 QEMU 的 argv[0]。

**Bug 2 — `/tmp` 可写+可执行依赖**(`cache_qemu_from_probe`,stub.c:2548/2565)

写 `/tmp/.antirev-qemu-aarch64` mode 0755。**只读容器 / `noexec /tmp`** 下失败,退回直接 fexecve,而那条在 x86 stub + aarch64 target 下基本必然失败(x86 kernel 跑不了 aarch64 memfd,只能靠 binfmt)。
**修法**:cache 路径可配(env / 探测可写可执行目录),或失败时有更稳的兜底。

---

## 3. 相关代码地图(stub/stub.c)

| 函数 | 行 | 作用 |
|---|---|---|
| `needs_qemu_for_fd` | 2458 | 读 ELF e_machine,判断是否跨架构需 QEMU |
| `build_qemu_argv` | 2477 | 构造 qemu 命令行(**Bug 1 在这**) |
| `try_exec_known_qemu` | 2497 | 试 `/tmp/.antirev-qemu-aarch64`、`/usr/bin/qemu-aarch64-static`、`/usr/bin/qemu-aarch64` |
| `wait_for_qemu_exe` | 2527 | 轮询 `/proc/<pid>/exe` 找含 "qemu" 的路径 |
| `cache_qemu_from_probe` | 2548 | fork→binfmt 拉 qemu→读 /proc/pid/exe→拷 /tmp→重 exec(**Bug 2 在这**) |
| `exec_target` | 2586 | dispatcher 总入口 |
| `__r_MF` 注入 | 2103 | `__r_MF=<main_fd>` 注入 fexecve 的 env |

exe_shim 侧(stub/exe_shim.c):
- `detect_owner` 行 191,QEMU 兜底在 **212-214**(/proc/self/exe 指向 qemu 时,靠 `__r_MF` presence 判 owner)—— 这条已是对的。

---

## 4. 环境现状(2026-05-28 探测结果)

- **Windows host,x86_64**
- **Docker:未安装**(bash 和 PowerShell 都没有 `docker`)
- **podman:无**
- **WSL:未安装** —— 只有 Windows 自带的 `wsl.exe` 启动器壳;`wsl --status` / `wsl --version` 都返回"未安装用于 Linux 的 Windows 子系统"
- **qemu:host 上无 qemu-aarch64-static**

---

## 5. 用户要做的一次性动作(需管理员 + 重启)

在**管理员 PowerShell**:

```powershell
wsl --install -d Ubuntu
# 重启
# 重启后 Ubuntu 自动起,设用户名+密码
```

验证:

```powershell
wsl -l -v       # Ubuntu  Running/Stopped  2
wsl uname -a    # x86_64 Linux
```

---

## 6. WSL 就绪后,Claude 接手的步骤(可从会话直接 `wsl bash -lc "..."` 驱动)

```
1. sudo apt update && sudo apt install -y \
       qemu-user-static binfmt-support \
       gcc-aarch64-linux-gnu cmake build-essential
2. 确认 binfmt 注册 aarch64:
   cat /proc/sys/fs/binfmt_misc/qemu-aarch64    # 应存在,看 F flag
3. 拉代码:仓库已在 Windows 侧 D:\code\codeanti-rev,
   WSL 里走 /mnt/d/code/codeanti-rev,或 git clone 一份到 WSL ext4(更快)
4. 构建:
   - x86_64 native stub(本机 gcc)
   - aarch64 shim + aarch64 demo 业务二进制(aarch64-linux-gnu-gcc 交叉编译)
   - daemon(arch 待定——只做 AES+socket,可 x86)
5. antirev-pack 打包:x86 stub 包 aarch64 hello-world(= 场景 B)
6. 跑:ANTIREV_LOG=<path> 运行,看 exec_target 走哪条分支、能否拉起 hello-world
7. 验 Bug 1(guest argv[0] 是不是 /proc/self/fd/N)+ Bug 2(noexec /tmp 行为)
8. M2:进 docker arm64 容器(qemu 不在 PATH、binfmt F-flag),验 cache_qemu_from_probe
```

---

## 7. 验证里程碑(从小到大)

| 里程碑 | 验什么 | 状态 |
|---|---|---|
| **M1 核心 dispatcher** | x86 stub 用 qemu 拉起加密 aarch64 hello-world;验 Bug1/Bug2 | ⏳ 等 WSL |
| **M2 Docker F-flag 路径** | 容器内 qemu 不在 PATH 时 cache_qemu_from_probe 能否工作 | ⏳ |
| **M3 全链路** | shim + daemon + dlopen 加密库在 QEMU 下跑通 | ⏳ |

---

## 8. 关键开放问题

- [ ] 场景 B 下 daemon 该是 x86 还是 aarch64?(只做 crypto+socket,倾向 x86 native)
- [ ] 场景 B 下 shim 必须是 aarch64(被 LD_PRELOAD 进 aarch64 业务进程)—— 构建要交叉编译 shim
- [ ] `/proc/self/fd/N` 跨 `execve(qemu)` 存活:main_fd 无 MFD_CLOEXEC(stub.c:332)✅,但 daemon socket `__r_LS` 等其他 fd 是否也要无 CLOEXEC 才能让 QEMU 下的子进程用?
- [ ] QEMU 把 guest argv[0] 设成 fd 路径后,业务软件有没有依赖 argv[0] 的逻辑
- [ ] CMake 是否支持"x86 stub + aarch64 其余"的混合构建,还是要手动分步编

---

## 9. 任务状态(TaskList)

- #18 探测 WSL 环境 — ✅ 完成(结论:WSL 未装)
- #19 M1 核心 dispatcher — ⏳ 等 WSL
- #20 M2 Docker probe-cache — ⏳ 等 WSL

---

## 10. 重启回来怎么续

把这份文件指给 Claude:"看 docs/qemu_scenarioB_verification.md,WSL 装好了,继续第 6 节"。
Claude 从第 6 节步骤 1 开始驱动 WSL。
