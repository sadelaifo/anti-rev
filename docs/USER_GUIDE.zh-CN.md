# antirev 用户指南（原始方案 / master 分支）

本指南面向**打包工程师**与**部署运维人员**，介绍 antirev 的原始保护方案（即 master
分支上的 **stub + shim + 守护进程（lrxd）+ 加密工具链** 架构）。这是当前正式发布、
经过现场验证的方案。

> 另有一套实验性替代架构 `kmod2/`（内核模块 `antirevfs`），不在本指南范围内，
> 参见 `kmod2/DESIGN.md`。本指南只讲原始方案。

---

## 1. 它解决什么问题

把可执行文件和共享库以密文形式存放在磁盘上，**运行时才在内存里解密**，从而防止
静态逆向：

- 磁盘上永远是密文（AES-256-GCM）。
- 解密后的明文只存在于 **memfd**（匿名内存文件），**从不落盘**。
- 进程用 `fexecve` 直接从 memfd 启动，`/proc/self/exe` 指向 `memfd:<随机名> (deleted)`，
  磁盘上看不到明文，也无法从进程名反查是哪个文件。

核心权衡：这是**静态**（data-at-rest）保护。CPU 执行的是明文，任何能 `cat /proc/<pid>/fd/N`
或 dump 进程内存的 root 都能拿到明文——这是所有此类方案的物理下限（见第 12 节威胁模型）。

---

## 2. 架构与组件

| 组件 | 作用 |
|---|---|
| **stub** | C 编写的启动器。把捆绑的密文解密进 memfd，再用 `fexecve` 执行。**无主程序时**它以守护进程（lrxd）模式常驻。 |
| **antirev_shim** | 唯一的 `LD_PRELOAD` 注入 `.so`（每种架构一个：`antirev_shim_x86_64.so` / `antirev_shim_aarch64.so`）。把所有拦截逻辑打成一个 DSO：`dlopen` 重定向、身份隐藏、（aarch64）`ANTI_LoadProcess` 劫持、热补丁 `.pat` 重定向等。 |
| **lrxd（守护进程）** | 轻量级“库服务器”。扫描 `$HOME/SW` 下的密文 `.so`/`.elf`，解密进 memfd，通过 Unix 套接字用 `SCM_RIGHTS` 把 fd 传给各个业务进程。多架构部署为 `lrxd-x86_64` / `lrxd-aarch64`。 |
| **encryptor（加密工具链）** | Python 工具：`protect.py`（单文件级操作）、`antirev-pack.py`（按 YAML 批量打包）、`build.py`（Python 源码混淆）、`miniyaml.py`（内置 YAML 解析）。 |
| **antirev_client.py** | 供 Python 脚本加载加密库：连守护进程、拿 memfd、透明改写 `import` 与 `ctypes.CDLL`。 |

> **无需 pip 依赖**：`protect.py` 通过 `ctypes` 直接调用系统 **libcrypto（OpenSSL）** 做
> AES-256-GCM，YAML 用内置 `miniyaml.py` 解析。所以打包机只需 **Python 3 + 系统 OpenSSL**，
> 不用 `pip install`。

---

## 3. 能保护哪些东西

| 保护对象 | 用什么 | 结果 |
|---|---|---|
| 可执行文件（主程序 ELF） | `protect.py protect-exe` 或 `antirev-pack.py` | 单个自包含的“受保护二进制”，或由守护进程供库的瘦身版 |
| 共享库 `.so` / 程序段 `.elf` | `protect.py encrypt-lib` 或 `antirev-pack.py` | 密文库，运行时由 lrxd 守护进程按需解密下发 |
| Python 脚本 | `build.py`（cython / nuitka / pyarmor） | 编译/混淆后的模块 |
| 热补丁 `.pat` | `protect.py encrypt-patch` | 密文补丁，运行时通过 antirev_shim 拉取（见第 11 节） |

---

## 4. 环境与前置条件

**打包机（离线）**
- Linux + Python 3
- 系统 OpenSSL（`libcrypto`）
- 交叉/本地工具链：`cmake`、`make`、`gcc`（对应目标架构；aarch64 需相应交叉编译器）
- `patchelf`（`antirev-pack.py` 处理库 SONAME 时用到）

**目标机（部署）**
- 与打包目标架构一致的 Linux（现场验证覆盖 SUSE SLES 12 SP5 x86_64 与 aarch64）
- glibc 动态链接器可用（stub 依赖 `ld.so` 常规解析流程）

---

## 5. 编译构建（生成 stub 与 shim）

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
```

产物（发布用）：
- `stub`（aarch64 为 `stub_aarch64`）——启动器兼守护进程二进制。
- `antirev_shim_x86_64.so` / `antirev_shim_aarch64.so`——注入 shim（已作为字节数组内嵌进 stub）。

> 跑测试套件（改动后务必执行）：
> ```bash
> cmake -DBUILD_DIR=build -DSRC_DIR=. -P cmake/run_all_tests.cmake
> ```

守护进程 `lrxd` 不由 `make` 直接产出，而是由 `protect.py protect-daemon` 或
`antirev-pack.py` 用 `stub` 生成（见第 7、8 节）。

---

## 6. 密钥与 keysplit（务必理解）

打包时你提供一个**十六进制密钥文件**（`--key`），不存在会自动生成（`0600`）。但真正用来
加密库/补丁的**并不是**这个裸密钥，而是 **keysplit 派生的“真实密钥”**：

```
真实密钥 = SHA256( part1 ‖ SHA256(lrxd 二进制) ‖ version 值 )
```

- **part1**：写在每个受保护二进制的尾部（trailer）里。
- **part2 = SHA256(lrxd)**：把部署到目标机的 `lrxd` 守护进程二进制整体做哈希。
- **version 值**：运行时执行目标机上的 `$HOME/SW/version` 并解析其输出得到，**必须**与打包
  时 `antirev-pack.py` 配置里的 `version:`（或 `--version`）逐字节一致。

**由此得到两条铁律：**
1. 目标机部署的 `lrxd` 必须与打包时使用的 `lrxd` **字节完全相同**（否则 part2 变了，解密失败）。
2. `$HOME/SW/version` 解析出的值必须与打包配置的 `version` 值**完全一致**。

keysplit 是**按架构**的（part2 是该架构 lrxd 的哈希），所以给哪种架构打补丁就用哪种架构的 lrxd。

---

## 7. 快速开始：保护单个可执行文件

```bash
# 1) 用 stub 把主程序 ELF 加密捆绑成一个自包含的受保护二进制
python3 encryptor/protect.py protect-exe \
    --stub   build/stub \
    --main   ./your_app \
    --key    ./proj.key \
    --output ./your_app.protected

# 2) 直接运行（进程镜像即受保护二进制自身）
./your_app.protected [参数...]
```

若该程序的依赖库交由守护进程供给，加 `--daemon-libs`（配合第 8/10 节的守护进程部署）。

单独加密一批共享库：
```bash
python3 encryptor/protect.py encrypt-lib \
    --key ./proj.key \
    --libs libfoo.so libbar.so \
    --output-dir ./enc_libs      # 省略则原地加密
```

生成守护进程：
```bash
python3 encryptor/protect.py protect-daemon \
    --stub build/stub --key ./proj.key --output ./lrxd
```

---

## 8. 批量打包：`antirev-pack.py` + YAML

真实项目（上百个可执行、数百个库）用配置文件一键打包。

```bash
python3 encryptor/antirev-pack.py config.yaml -j 8
```

### 配置字段速查

| 字段 | 说明 |
|---|---|
| `install_dir` | 待扫描的安装树（明文源） |
| `output_dir` | 打包输出目录（密文树） |
| `key` | 十六进制密钥文件路径（相对配置文件；不存在则创建） |
| `stub` | 单架构 stub 路径；或用 `stubs:` 指定多架构映射 |
| `stubs:` | `{arch: 路径}` 映射，如 `x86_64: ...` / `aarch64: ...` |
| `libs` | `encrypt`（默认，加密库）等模式 |
| `encrypt_libs` | 白名单：**只**加密列出的库，其余明文拷贝 |
| `plaintext_libs` | 黑名单：列出的库保持明文，其余全部加密（与 `encrypt_libs` 二选一） |
| `blacklist` | 完全不处理、按需排除的文件（glob，如 `*.py`、`out/` 子树） |
| `copy` | 需原样拷贝到输出的文件（glob） |
| `lrxd:` | `{arch: 目标路径}`，每次打包都会构建对应架构的守护进程并放到此处 |
| `version` | keysplit 的 version 值（见第 6 节）；必须与目标机 `$HOME/SW/version` 解析结果一致 |

> 数值型标量**保持字符串**：`version: 1.20` 不会被解析成浮点 `1.2`（那会悄悄改掉密钥）。
> 需要时再加引号。

### 示例配置

```yaml
install_dir: .
output_dir: ./protected
key: ./proj.key
stub: ../../build/stub
libs: encrypt

# 只加密这两个库，其余（如第三方库）保持明文
encrypt_libs:
  - libfoo.so
  - libtee.so

blacklist:
  - "*.py"
  - "*.yaml"
  - "*.sh"
  - "*.key"
  - protected/          # 排除输出目录自身
```

多架构与守护进程落位：
```yaml
stubs:
  x86_64:  ../../build/stub
  aarch64: ../../build-arm/stub_aarch64
lrxd:
  x86_64:  ./protected/bin/sw/lrxd-x86_64
  aarch64: ./protected/bin/sw/lrxd-aarch64
version: "V100R001C00"
```

**命令行覆盖**（优先级 CLI > 配置）：`--install-dir` / `--output-dir` / `--key` /
`--stub` / `--lrxd`（单架构）/ `--version`。配置也可用位置参数或 `--config FILE` 给出。

---

## 9. 保护 Python 脚本：`build.py`

```bash
# cython（快）/ nuitka（独立可执行）/ pyarmor（混淆）三选一
python3 encryptor/build.py cython \
    --mains-dir ./scripts --libs-dir ./pylibs --output-dir ./pybuild -j 8
```

若 Python 需要加载加密的 `.so`，在脚本内启用客户端：
```python
from antirev_client import activate
activate()   # 连守护进程，打补丁 import / ctypes.CDLL，重定向到 memfd 库
```

---

## 10. 部署布局与运行

### 安装树

守护进程把 **`$HOME/SW`** 当作扫描根（`$HOME/SW` 不存在时退回自身所在目录）。推荐布局：

```
$HOME/SW/
├── version                 # 可执行，打印版本串（keysplit 的 version 来源）
├── bin/
│   └── sa/
│       └── lrxd[-arch]     # 守护进程（其字节哈希 = keysplit part2）
├── bin/<模块>/<受保护可执行>
└── lib/<模块>/<密文库.so>
```

把 lrxd 放在子目录、库放在别处也可以——扫描根锁定在整棵 `$HOME/SW` 树。

### 启动顺序

```bash
# 1) 先起守护进程（常驻；扫描 $HOME/SW，建立 socket，解析各库 DT_NEEDED 依赖图）
$HOME/SW/bin/sw/lrxd &

# 2) 再运行受保护的可执行文件；它们会：
#    - 自动继承 antirev_shim 的 LD_PRELOAD
#    - 通过继承的守护进程连接（__r_LS）按需拉取加密库
#    - DT_NEEDED 库经 LD_LIBRARY_PATH 上的符号链接目录解析，保持原符号查找顺序
$HOME/SW/bin/<模块>/<受保护可执行> [参数...]
```

守护进程通过 `SCM_RIGHTS` 把 memfd 的 fd 传给客户端；DT_NEEDED 库走 glibc 正常 BFS 解析
（`LD_PRELOAD` 里**只有** antirev_shim 一项），`dlopen` 的加密库在首次打开时按需拉取其
加密依赖闭包。

---

## 11. 运行时环境变量（部署可调）

在**顶层启动脚本**（每个受保护进程的公共父进程）里 export，才能被所有子进程继承。

| 变量 | 作用 |
|---|---|
| `__r_NP=1` | **关闭逐依赖预加载**。适用于库间存在隐式符号依赖（没有显式 `DT_NEEDED` 边）的应用——让 glibc 走原生递归加载，最贴近明文语义。按应用可选开启。 |
| `__r_FX=1` | **docker + qemu-user 部署专用**。强制显式 QEMU 分发，让被 exec 的 guest 保留真实 `argv[0]`（否则 binfmt 会丢掉程序名，导致按名字找进程的重启/保活脚本失效、端口 `EADDRINUSE`）。必须在顶层脚本 export。 |
| `ANTIREV_DLOPEN_LOG=<path>` | 记录每次 dlopen 决策、闭包拉取、预加载与失败——排查 dlopen/闭包问题必备。 |
| `ANTIREV_PATCH_LOG=<path>` | 记录 `.pat` 热补丁的 open 决策与守护进程拉取。 |
| `ANTIREV_AARCH64_EXTEND_LOG=<path>` | （aarch64）记录每次 `ANTI_LoadProcess` 调用、路径改写决策与拉取结果。 |

### 热补丁（`.pat`）

```bash
# 打包侧：用 keysplit 真实密钥加密补丁（需与目标同架构的 lrxd 与一致的 version）
python3 encryptor/protect.py encrypt-patch \
    --key ./proj.key --patches fix001.patch \
    --lrxd $HOME/SW/bin/sw/lrxd --version V100R001C00 \
    --output-dir ./enc_patches
```
部署侧：把密文 `.pat` **放到 `$HOME/SW` 下任意位置**即可。已在运行的受保护进程通过内嵌于
antirev_shim 的重定向 + 继承的守护进程连接自动拉取解密（无需重启、无需单独 preload、无发现文件）。

---

## 12. 安全边界（威胁模型）

- **保护的是静态数据**：磁盘密文 + 运行时内存解密。防的是“把软件目录拷走做静态逆向”。
- **明文一定在 RAM 里**：CPU 执行明文，ring-0/root 总能读到——这是物理下限，本方案（以及任何
  纯软件方案）都无法突破。只有硬件内存加密（SEV-SNP/TDX/enclave）能改变此结论，超出本方案范围。
- **memfd 隐藏的是外部观测**：`ls /proc/<pid>/fd`、`cat /proc/<pid>/maps` 无法区分哪个 fd 装了
  哪个加密件（每进程随机 memfd 名）；但能 `cat /proc/<pid>/fd/N` 的人仍可读到明文。
- **建议叠加**：出厂时用 **TPM 按单机封存** AES 密钥，使被拷走的密文即便到了别处也无法解密/异机运行。

---

## 13. 排错速查

**先解出真实 errno，别信 `ld.so` 的笼统提示**（“cannot open shared object file” 有多种成因）：

| 现象 | 含义 |
|---|---|
| `Permission denied` (`EACCES`) | 权限/身份问题 |
| `Required key not available` (`ENOKEY`) | 密钥不可用（keysplit 派生失败——多为 lrxd 不一致或 version 不匹配） |
| `No such file or directory` (`ENOENT`) | 不在搜索路径，或找到了但内容非法（拿到密文/架构不符） |
| `Read-only file system` / `Error 30` (`EROFS`) | 往只读位置写文件 |

**常用检查脚本**（`tools/` 下）：
- `check_encrypted.sh`——确认文件确实是密文。
- `check_env.sh` / `diff_stub_envs.sh`——核对运行时环境变量。
- `check_runtime_lib.sh`——检查运行时库解析。
- `missing_syms.py`——重复符号 / 缺失符号扫描（排查 ODR、符号插桩问题）。

**keysplit 不匹配自查**：
- 目标机 `lrxd` 与打包用的是否字节一致？（`sha256sum` 对比）
- `$HOME/SW/version` 的输出解析值是否等于配置 `version`？可用 `tools/keysplit_expect.py --version <值>`
  或 `--version-script <脚本>` 复现运行时解析规则。

---

## 14. 命令速查

```bash
# 构建
mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make

# 单文件
python3 encryptor/protect.py protect-exe    --stub build/stub --main APP --key K --output OUT
python3 encryptor/protect.py encrypt-lib    --key K --libs L1.so L2.so [--output-dir DIR]
python3 encryptor/protect.py protect-daemon --stub build/stub --key K --output lrxd
python3 encryptor/protect.py encrypt-patch  --key K --patches P.patch --lrxd LRXD --version V [--output-dir DIR]

# 批量
python3 encryptor/antirev-pack.py config.yaml -j 8

# Python 混淆
python3 encryptor/build.py {cython|nuitka|pyarmor} --mains-dir M --libs-dir L --output-dir O

# 测试
cmake -DBUILD_DIR=build -DSRC_DIR=. -P cmake/run_all_tests.cmake

# 运行（目标机）
$HOME/SW/bin/sw/lrxd &                       # 先起守护进程
$HOME/SW/bin/<模块>/<受保护可执行> [参数...]   # 再跑业务
```

---

*本指南对应 master 分支的原始 antirev 方案。若架构/命令发生变化，请同步更新本文件与
`CLAUDE.md`。*
