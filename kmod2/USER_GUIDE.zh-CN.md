# antirevfs 用户指南（kmod2 内核模块方案）

本指南面向**打包工程师**与**部署运维人员**，介绍 antirev 的替代架构 **`antirevfs`**——
一个只读的**堆叠式加密内核文件系统**。它用一个内核模块取代原始方案的整套
stub + shim + 守护进程（lrxd）+ `antirev_client.py`。

> 原始方案（stub/shim/daemon）见仓库根目录 `docs/USER_GUIDE.zh-CN.md`，是当前正式发布的方案。
> antirevfs 是可用的 PoC/v1，设计细节见 `kmod2/DESIGN.md`。两者**二选一**，不要混用。

---

## 1. 它是什么，好在哪

密文放在下层 `.enc/` 目录树里，`antirevfs` 挂载在其上，在**缺页时（`read_folio`）**解密
`ANTREV01`（AES-256-GCM）文件。相比原始方案：

- **无守护进程、无 `LD_PRELOAD`、无 `memfd:`**——`/proc/<pid>/maps` 里看不到 memfd 痕迹。
- **原生符号解析**：glibc / `ld.so` / Python 看到的是**真实路径上的明文**，因此原始方案里
  隐式 `DT_NEEDED` / ODR 那些痛点（`__r_NP` 之类）在这里自然消失。
- **内核页缓存自带跨进程共享**：多个进程映射同一路径，共用同一份解密后的物理页。

代价与边界：这仍是**静态**（data-at-rest）保护。挂载点是真实路径，会把明文交给任何被授权的
读者；CPU 执行明文，root 总能读到——见第 12 节威胁模型。

---

## 2. 工作原理（一次 open 的路径）

`open("/proj/lib/foo.so")`：

1. VFS 走到 `/proj/lib`——antirevfs 挂载点，改用 antirevfs 的操作表。
2. `lookup` 解析到下层 `.enc/` 里的密文文件（真实 ext4）。
3. `open` 读文件尾部魔数：命中 `ANTREV01` → 走解密路径；否则按 `passdata`/`passthrough` 决定
   是否明文放行，都不满足则 `-EIO`（strict 模式）。
4. `mmap` / 首次缺页 → `read_folio` 从下层读密文，用**文件内嵌的密钥**整文件一次性解密（GCM
   整消息校验 tag），写入 per-inode 缓冲，之后按页服务。
5. 页缓存持有明文；其它进程映射同一 inode 直接共享物理页。

---

## 3. 磁盘格式：内嵌密钥尾部（无挂载密钥）

```
[magic ANTREV01 : 8] [iv : 12] [tag : 16] [密文 ct ...] [key : 32] [magic ANTREV01 : 8]
       └── HDR(36) ──┘                     └──────── TRAILER(40) ────────┘
明文长度 = 下层文件大小 − HDR(36) − TRAILER(40)
```

- **没有挂载密钥、没有 keyring、没有 `key=` 选项**：每个文件把自己的 AES 密钥放在尾部，模块在
  解密时现读（用完 `memzero_explicit` 抹掉）。挂载是**零密钥**的。
- **未授权读者**通过挂载看到的是**去掉尾部（40 字节）的容器**——一个看起来合法、但缺密钥、
  无法解密的 `[magic][iv][tag][ct]`。
- **重要权衡**：密钥现在就在 `.enc/` 文件里，所以**原始拷贝下层 `.enc/` 树是可解密的**。保护依赖
  两点：① 挂载对未授权读者剥掉尾部；② `.enc/` 树保持**命名空间隔离**（见第 12 节）。

---

## 4. 组件一览

**模块源码**（`kmod2/module/`）
| 文件 | 作用 |
|---|---|
| `super.c` | 文件系统注册、`mount_nodev`、选项解析、inode/sb 生命周期（**不取密钥**，挂载零密钥） |
| `inode.c` | lookup 代理到下层、inode 缓存（按下层 dentry，一个路径共享一份页缓存）、getattr 报明文大小、**符号链接支持** |
| `file.c` | `read_folio` 解密、目录 `iterate_shared`、以及未授权读者的“剥尾部”透传 ops |
| `crypto.c` | `gcm(aes)` 内核 crypto API；从尾部读每文件密钥 |
| `gate.c` | 解密授权门（见第 9 节） |
| `compat.h` | 跨内核兼容垫片（6.8 → SLES 4.12） |

**工具**（`kmod2/tools/`）
| 工具 | 作用 |
|---|---|
| `antirev-fs-pack.py` | 打包器：把安装树里每个 ELF 加密成内嵌密钥容器，产出密文下层树 + JSON 清单 |
| `antirev-mount` | `mount -t antirevfs` 封装，**只读**视图（零密钥） |
| `antirev-mount-rw` | **可写**视图：在只读 antirevfs 之上叠加 overlayfs 可写上层 |
| `antirev-mount-inplace.sh` | **就地覆盖挂载**（Model B，PoC，未测试）——密文与挂载点同路径 |
| `antirev-remount-proj.sh` | 参考部署脚本：一键 umount→rmmod→insmod→挂载两棵树 |
| `antirev-keyctl` | **已废弃**（密钥现在按文件内嵌，无挂载密钥），仅为旧流程保留 |

---

## 5. 内核兼容与编译

**必须用内核自身编译器的主版本号来编译**（module 加载由 vermagic=内核版本控制，但过大的
gcc 跨版本会触发更严格的诊断报错）：

```bash
# 6.8 开发机：
make -C kmod2/module CC=gcc-12

# SLES 12 SP5（内核用 gcc 4.8.5 编）：先装 kernel-default-devel + gcc48
make -C kmod2/module CC=gcc-4.8
```

已在 **mainline 6.8.0-117/124** 与 **SLES 12 SP5 `4.12.14-120-default`** 两端运行验证。
`compat.h` 用 `LINUX_VERSION_CODE` 守卫覆盖 `read_folio`↔`readpage`、crypto 异步等待、getattr
签名、`kernel_read` 签名、`FMODE_EXEC` 两处落点等差异；企业内核回移新 API 但保留旧版本号时，
用 `-DAREV_*` 覆盖宏处理（例如 `make EXTRA_CFLAGS=-DAREV_NEW_KERNEL_READ`）。

加载模块（先关门，便于分阶段验证）：
```bash
sudo insmod kmod2/module/antirevfs.ko gate_enforce=0
cat /sys/module/antirevfs/refcnt          # 每个存活挂载 +1
```

---

## 6. 打包：`antirev-fs-pack.py`

```bash
python3 kmod2/tools/antirev-fs-pack.py config.yaml            # 产出密文下层树
python3 kmod2/tools/antirev-fs-pack.py config.yaml --dry-run  # 只分类不写盘
```

它按 **ELF 魔数**（不是扩展名）加密**每个 ELF**（库和可执行都加密），产出镜像化的
`output_dir/` 密文树，并把 JSON 清单写在树**之外**。

### 配置字段

| 字段 | 说明 |
|---|---|
| `install_dir` | 待扫描的安装树（明文源，必填） |
| `output_dir` | 密文下层树输出目录（必填，须不同于 `install_dir`） |
| `key` | 十六进制密钥文件（相对配置文件；不存在则以 `0600` 创建） |
| `blacklist` | **保持明文**的 ELF：basename glob（如 `libprotobuf.so*`）或**子树前缀**（如 `link/3rd/`） |
| `mirror_plaintext` | 默认 **true**：把非 ELF 文件（`.py/.pyc/.sh/.txt/.json`…）和黑名单 ELF **原样明文镜像**进树，符号链接也重建，得到完整混合内容树；设 false 则只有加密 ELF + 符号链接进树 |

> ⚠️ **黑名单子树必须带结尾 `/`**。`link/3rd`（无斜杠）会被当作 **basename glob**，匹配不到任何
> 目录下文件，导致该目录被加密。正确写法：`link/3rd/`、`lib/3rd/`。

### 示例

```yaml
install_dir: /root/proj_src          # 明文源
output_dir:  /root/proj_protect      # 密文下层树
key:         proj.key.hex
mirror_plaintext: true
blacklist:
  - lib/link/3rd/                    # 第三方库子树，保持明文（结尾斜杠！）
  - libPreload.so                    # 全局预加载库，必须明文（见第 11 节）
```

打包后核对清单：
```bash
grep -A20 '"encrypted"' antirev-fs-manifest.json   # 应加密的在这里
grep -A20 '"plaintext"' antirev-fs-manifest.json   # 第三方/数据文件在这里
```

---

## 7. 三种挂载方式

### 7.1 只读视图 `antirev-mount`

```bash
sudo kmod2/tools/antirev-mount --passdata <密文下层树> <挂载点>
```
`--passdata`：任何非 `ANTREV01` 文件按明文透传（配合 `mirror_plaintext` 的混合内容树）。
只允许特定扩展名透传时用 `[passthrough-exts]`（冒号分隔，如 `json:md`）。

### 7.2 可写视图 `antirev-mount-rw`（业务在 `bin/`/`lib/` 里写文件时用）

裸 antirevfs 是**三重只读**（`SB_RDONLY` + 无 `write_folio` + 目录 iops 无 create/unlink），
业务写锁/日志/pid 会 `-EROFS`。方案：保持 antirevfs 只读，在其上叠一层 overlayfs 可写上层。

```bash
sudo kmod2/tools/antirev-mount-rw --passdata <密文下层树> <挂载点>
sudo kmod2/tools/antirev-mount-rw --down <挂载点>          # 拆除（先 overlay 后 antirevfs）
```
- 解密的 `.so`/`.elf` 读**穿透**到 antirevfs 下层；运行时写落到 overlay 上层，**永不触碰** `.enc/` 密文。
- 层目录默认在 `<挂载点父目录>/.antirev-rw/<挂载点名>/{dec,upper,work}`；`--state <dir>` 可指到
  tmpfs 以便重启即弃。
- **拷贝上行注意**：overlayfs 首次**改写一个已存在的加密文件**时会把它**以明文**复制到上层
  （业务不会这么做；新建锁/日志文件不会触发）。

### 7.3 就地覆盖挂载 `antirev-mount-inplace.sh`（Model B，PoC，未测试）

密文与挂载点**同路径**，无并行 `.enc/` 树、无 `.antirev-rw`——`ls` 前后字节一致。写位置用
匿名 tmpfs / bind 处理。编辑脚本顶部 `MOUNTS`/`WRITE_DIRS`/`WRITE_FILES` 后：
```bash
sudo kmod2/tools/antirev-mount-inplace.sh up      # 重载模块 + 就地挂载
sudo kmod2/tools/antirev-mount-inplace.sh status
sudo kmod2/tools/antirev-mount-inplace.sh down
```
> ⚠️ 就地覆盖（下层 == 挂载点）**尚无测试覆盖**，投产前请在你的内核上先验证。

---

## 8. 解密授权门（gate）

只有**被授权的进程**才能打开加密文件、经共享页缓存拿到明文；`cp`/备份/文件管理器只能读到
下层 `.enc/` 密文。策略只作用于**加密文件**，用 `-EACCES` 拒绝。模块参数（都是 `0644`，可运行时改）：

| 参数 | 默认 | 说明 |
|---|---|---|
| `gate_enforce` | `0`（放行所有） | 1 = 启用白名单强制 |
| `authz_path` | `/etc/authorized_apps.txt` | 白名单文件路径，每次 open 重读（可热改） |
| `gate_passthrough_cipher` | `0`（硬 `-EACCES`） | 1 = 未授权读返回**去尾部的密文**（`cp`/`objdump` 拿到无密钥容器而非报错） |

**执行加载 vs 数据读，用不同身份**（关键）：
- **执行一个加密可执行**：内核在 `exe_file` 尚未切换前打开程序（`FMODE_EXEC`），故按**程序自身路径**
  授权（否则任何加密程序都无法启动自己）。
- **其它 open（库加载、`cp`、`source`）**：按**调用进程的 exe**（`current->mm->exe_file`）授权——这正是
  让 `cp` 只能读到密文的原因。

因此：一个受信程序能运行，其加密库加载也放行（运行中的 exe == 白名单）；而 `cp` 同一文件被拒。
`fork()` 继承授权；`execve` 换成未列名的助手（如 shell 调 `/bin/cp`）自动丢授权。

**白名单写法**：一行一个；含 `/` 匹配全路径，不含 `/` 匹配 basename；`#` 注释、空行忽略。
```bash
# /etc/authorized_apps.txt —— 强烈建议用 basename
processManager
executable_x
python3                 # python 加载加密 .so 时，按解释器身份授权
qemu-aarch64-static     # sim 模式，见第 10 节
```

运行时切换（无需重载）：
```bash
echo 1 | sudo tee /sys/module/antirevfs/parameters/gate_enforce
```

---

## 9. 参考部署布局

密文下层树 `/root/proj_protect/{bin,lib}`，挂到 `/root/proj/{bin,lib}` 作为**可写 overlay 视图**
（`antirev-mount-rw`）+ `passdata` + `gate_enforce=1` + `/etc/authorized_apps.txt`；业务设了全局
`LD_PRELOAD` 指向自定义 `libPreload.so`。**`bin/` 和 `lib/` 都可写**（业务在两处都写运行时文件）。

一键脚本自动完成 umount→rmmod→insmod→挂载两棵树：
```bash
sudo bash kmod2/tools/antirev-remount-proj.sh
# 默认 LIB_WRITABLE=1（lib/ 可写）；设 0 则 lib/ 只读
```

---

## 10. sim 模式：ARM64-on-x86（qemu-user）

部署有 **ARM64 RTOS 从机**，在 **x86-64 host** 上用 **`qemu-user-static`**（binfmt_misc）跑，
有时在 **Docker** 里。**qemu-user 路径已验证**（`test_antirevfs_qemu.sh` 10/10）；**Docker 命名空间
集成仍未测试**。

- **解密与架构无关**：x86 的 `.ko` 逐字节服务 AARCH64 ELF；qemu 通过 host 内核 `open`/`mmap`
  ARM64 二进制 → 命中 antirevfs → 明文 ARM64 字节被模拟执行。
- **门按模拟器身份授权**：qemu-user 下进程的 `exe_file` 是 **`qemu-aarch64-static`**，不是那个
  ARM64 程序。所以 ARM64 库/数据读要**白名单 `qemu-aarch64-static`**；透明运行的加密 ARM64
  **可执行**还需要它**自身 basename**（host 内核在 binfmt 重定向前以 `FMODE_EXEC` 打开它）。
- **Docker 待办**：挂载须在容器挂载命名空间可见（bind/volume）→ 容器内暴露明文；`authz_path`
  解析到**容器的** `/etc`（白名单要放容器里）；`d_path` 是容器相对的 → 用 **basename**。

---

## 11. 部署陷阱（现场踩过的坑）

- **全局预加载库（及其整条 `DT_NEEDED` 闭包）必须明文。** `LD_PRELOAD` 被每个后代继承，门按
  **消费进程**身份授权加密文件——加密的预加载库要给每个继承它的进程都白名单，不现实。把
  `libPreload.so` 及其第三方依赖（如 `link/3rd` 里的 `libsecurec.so`）保持明文；打包时**黑名单整个
  `link/3rd/` 子树**。
- **inode 分类会缓存，换密文↔明文后必须重挂。** antirevfs 首次 lookup 时决定“加密/明文”并缓存；
  改了下层文件后不重挂，旧分类会导致读失败。
- **ld.so 失败要看真实 errno，别信笼统文案。** 直接 `head -c 16 <lib> | xxd` 或查 errno：
  `Permission denied`=`EACCES`=门（进程没白名单，或文件还是密文）；`No such file or directory`=`ENOENT`=
  不在搜索路径，或找到但非法 ELF（拿到密文/架构不符）；`Read-only file system`=`EROFS`=往只读挂载里写。
- **`antirev-mount-rw` 下白名单必须用 basename。** 同一程序在执行加载与数据读两个检查点会呈现
  **两个不同绝对路径**（一个是 overlay 下 `dec/` 路径，一个是 overlay 顶 `/root/proj/...`），只有
  **basename 相同**。全路径条目无法同时匹配一个二进制生命周期的两半。
- **Python 加载器按解释器身份授权。** 子进程 `import` 加密 `.so`，除非**解释器**（`python3` 等，按
  实际 exec 的 basename）在白名单，或该 `.so` 是明文。第三方扩展模块优先保持明文。
- **模块重载需要“静默栈”。** mmap 的 `.so` 会钉住超级块（进而钉住模块），`rmmod` 前先停业务；残留的
  `antirev-mount-rw` `dec` 挂载也钉模块，先 `--down` 收掉。查 `/sys/module/antirevfs/refcnt`（每个存活
  挂载为 1）。

---

## 12. 安全边界（威胁模型）

- **保护静态数据，不保护运行中数据。** 挂载点是真实路径，会把明文交给被授权读者；从应用上下文
  `cp /proj/lib/foo.so /usb/` 会带走明文 ELF——**挂载视图**就是泄露面。
- **两级对手：**
  - **在场对手 = 客户**：物理拥有软硬件，但是**非技术操作员**（GUI/拖拽/拷 U 盘），不懂 root/命名
    空间/解密/内存取证。攻击=“把软件目录拷走给别人”。
  - **有能力对手 = 竞品**：逆向专家，但**接触不到运行中的设备**，只拿到菜鸟拷走的字节。
  - **结论**：问题归约为“非技术用户能拷走的必须是密文”。
- **首要缓解——用命名空间隔离明文挂载**：用 `unshare -m`（或 systemd `PrivateMounts=yes`）在私有
  挂载命名空间里挂 antirevfs，普通 GUI 会话只看到 `.enc/` 密文树。
- **内嵌密钥方案下的告诫**：整盘/U 盘拷贝会连**内嵌密钥一起**带走 `.enc/`，所以命名空间隔离 +
  挂载剥尾部是现在承重的保护，密钥保护（尾部混淆 / TPM 封存）是后续工作。
- **物理下限**：CPU 执行明文 → 明文在 RAM → ring-0/root 总能读到，任何内核 FS 技巧都无法突破，
  只有硬件内存加密（SEV-SNP/TDX/enclave）能改变——超出范围。

---

## 13. 排错速查

```bash
# 挂载视图应是明文，下层应是密文：
head -c 16 <挂载点>/lib/foo.so     | xxd     # 明文 ELF: 7f 45 4c 46 ...
head -c 16 <密文树>/lib/foo.so     | xxd     # 密文: ANTREV01 (41 4e 54 52 45 56 30 31)

# 门是不是元凶？临时关掉对照：
echo 0 | sudo tee /sys/module/antirevfs/parameters/gate_enforce

# 模块钉住排查：
cat /sys/module/antirevfs/refcnt
dmesg | tail                                 # 门的拒绝决策等
```

---

## 14. 测试（root）

```bash
sudo bash kmod2/tests/test_antirevfs.sh              # 解密/密文在盘/dlopen/strict/passdata/符号链接…
sudo bash kmod2/tests/test_antirevfs_overlay_rw.sh   # 可写视图：EROFS→overlay 写入落上层
sudo bash kmod2/tests/test_gate.sh                   # 授权门：授权读放行、cp/cat 拒绝、execve 生命周期
sudo bash kmod2/tests/test_gate_passthrough.sh       # 去尾部密文透传
sudo bash kmod2/tests/test_gate_whitelist.sh         # 多程序白名单
sudo bash kmod2/tests/test_gate_access_matrix.sh     # {执行/读/写}×{列名/未列名} 矩阵
sudo bash kmod2/tests/test_antirevfs_qemu.sh         # sim 模式 ARM64-on-x86
sudo bash kmod2/tests/test_fs_pack.sh                # 打包器（无需 root）
sudo bash kmod2/tests/test_proj_setup.sh             # 业务栈复现（gate + overlay-rw + 相对路径 exec）
```

---

## 15. 命令速查

```bash
# 编译 + 加载（关门起步）
make -C kmod2/module CC=<内核的gcc>
sudo insmod kmod2/module/antirevfs.ko gate_enforce=0

# 打包
python3 kmod2/tools/antirev-fs-pack.py config.yaml        # [--dry-run]

# 挂载（三选一）
sudo kmod2/tools/antirev-mount    --passdata <密文树> <挂载点>          # 只读
sudo kmod2/tools/antirev-mount-rw --passdata <密文树> <挂载点>          # 可写；--down 拆除
sudo kmod2/tools/antirev-mount-inplace.sh up                           # 就地(PoC)

# 开门 + 白名单（basename）
echo 1 | sudo tee /sys/module/antirevfs/parameters/gate_enforce
sudoedit /etc/authorized_apps.txt

# 参考部署一键
sudo bash kmod2/tools/antirev-remount-proj.sh
```

---

*本指南对应 `kmod2-antirevfs` 分支的 antirevfs 内核模块方案。若模块/工具发生变化，请同步更新本文件、
`kmod2/DESIGN.md` 与根目录 `CLAUDE.md`。*
