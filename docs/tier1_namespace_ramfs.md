# Tier-1 替代实现:私有 mount namespace + 内存文件系统

> 状态:**设计提案 / 待可行性验证**
> 目标层级:Tier 1(挡磁盘 / 随便看,不挡本地 root 读内存)
> 核心收益:**彻底消除符号解析地狱**(隐式依赖 / 符号冲突 / RPATH / `__r_NP` / ctor 顺序)

---

## 0. 一句话摘要

把解密后的库放进一个**只有受保护进程树可见的内存文件系统**,挂在它**正常的路径上**,让 glibc 的动态链接器做 **100% 标准加载** —— 不再需要 LD_PRELOAD、symlink 目录、memfd 路径欺骗,因此所有符号问题从根上消失。安全强度与当前 memfd 方案完全相同(都是 Tier 1)。

---

## 1. 背景:符号地狱的根源

当前 memfd 方案的本质是:

> 把明文藏在一个 glibc **不认识**的地方(`/proc/self/fd/N`),然后想尽办法骗它去那里找。

为了"骗成功",衍生出了一整套机制,每一个都带来自己的问题:

| 机制 | 存在的原因 | 衍生的问题 |
|---|---|---|
| LD_PRELOAD shim | 拦截 readlink/dlopen 等,重定向到 memfd | 子进程继承、owner 检测、popen 损坏 |
| symlink 目录 + LD_LIBRARY_PATH | 让 glibc 的 DT_NEEDED 能找到 memfd | 生命周期管理、清理、跨进程 |
| 逐依赖 RTLD_GLOBAL 预加载 | memfd 库之间互相找符号 | ctor 隔离运行 → 跨隐式边界崩溃 |
| `__r_NP` 逃生开关 | 上面那条崩了时退回自然加载 | RPATH 指向密文目录 → 撞密文 |
| 每库随机 memfd 名 | 防 `/proc` 指纹 | 与符号问题无关,但增加复杂度 |

**所有这些问题的共同根源是:我们在对抗动态链接器。** 只要继续喂给它"碎片化 + 加密 + 路径与身份不符"的库,它就会用各种奇怪方式报复。

---

## 2. 核心思想:顺着 loader,而不是对抗它

> **把明文放在 glibc 本来就会去找的地方(正常路径、正常文件名),但只让受保护的这一棵进程树看得见。**

实现这个"只让一棵进程树看得见"的,是 Linux 的两个标准原语:

### 2.1 mount namespace

普通进程共享全局挂载表。`unshare(CLONE_NEWNS)` 给进程一份**私有的挂载表**:

- 它在私有视图里做的挂载,**其他进程完全看不见**
- **子进程继承**这个视图(业务进程的所有 fork / exec 都在里面)
- 进程树全部退出后,namespace 自动销毁,里面的挂载随之消失

### 2.2 tmpfs / ramfs

纯内存文件系统:

- 写进去的文件只在 RAM(page cache),**不落盘**
- **ramfs**:连 swap 都不碰(没有大小上限,需自己防 OOM)
- **tmpfs**:有大小上限,但**可能被换出到 swap**(明文落 swap 的风险,见 §7.3)

### 2.3 组合效果

```
受保护进程树的私有视图               宿主上其他进程看到的
┌──────────────────────────┐        ┌──────────────────────────┐
│ /opt/app/lib/             │        │ /opt/app/lib/             │
│   libfoo.so   ← 明文       │        │   (空 / 未挂载)            │
│   libbar.so   ← 明文       │        │                           │
│   (ramfs,在 RAM 里)       │        │ /opt/app/lib_enc/         │
│                           │        │   libfoo.so   ← 密文       │
└──────────────────────────┘        │   libbar.so   ← 密文       │
                                     └──────────────────────────┘
        ↑ 私有 mount namespace               ↑ 全局视图
          里的 ramfs 挂载                       看不到上面那个 ramfs
```

---

## 3. 启动流程(stub 改造)

```c
// Phase 0:先把密文读进内存,或把密文放在不被 ramfs 覆盖的目录
//          (挂载会盖住挂载点,得先能拿到密文)

// Phase 1:开 user namespace + mount namespace(无特权路径)
if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
    // 失败 → 回退到 memfd 方案,或报错
}

// Phase 2:uid/gid 映射,让自己在 ns 内是 "root"(才有权 mount)
write_file("/proc/self/setgroups", "deny");
write_file("/proc/self/uid_map",  "0 <real_uid> 1");
write_file("/proc/self/gid_map",  "0 <real_gid> 1");

// Phase 3:让挂载传播变 private,不外泄到宿主
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

// Phase 4:在 lib 目录上盖一层内存文件系统
//          ramfs = 不会被 swap 出去(推荐);也可用 tmpfs+size
mount("antirev", "/opt/app/lib", "ramfs", 0, NULL);

// Phase 5:逐个解密到【正常名字】
for (each enc lib) {
    plaintext = aes_gcm_decrypt(ciphertext, key);
    int fd = open("/opt/app/lib/libfoo.so", O_CREAT | O_WRONLY, 0500);
    write(fd, plaintext, len);
    close(fd);
    explicit_bzero(plaintext, len);   // 堆上明文立即擦除
}

// Phase 6:exec —— glibc 从 /opt/app/lib 正常加载
execve("/opt/app/bin/app", argv, envp);
```

执行 Phase 6 之后,业务进程看到的就是一个**普通的库目录**,glibc 用标准流程加载。

---

## 4. 为什么符号地狱彻底消失

业务进程的 glibc 看到的是 `/opt/app/lib/libfoo.so` —— **正常路径、正常 SONAME、内容完整**。于是:

| 之前的痛点 | 现在 |
|---|---|
| memfd 路径 `/proc/self/fd/N`,glibc 不认 | 正常路径,glibc 当普通库 |
| 需要 LD_PRELOAD 注入 shim | **不需要** |
| 需要 symlink 目录骗 DT_NEEDED | **不需要** |
| RPATH 指向密文目录 → 撞密文 | RPATH 指向 `/opt/app/lib` → 撞明文,正常 |
| 隐式依赖 / `__r_NP` 兜底 | **glibc 自然递归加载,顺序天然正确** |
| 符号冲突 dedup 依赖 scope 技巧 | **标准 global scope dedup** |
| ctor 跨库顺序崩溃 | **标准拓扑序,不崩** |
| C++ vague linkage(vtable/typeinfo)冲突 | **跟原生加载完全一致** |

**核心:你不再骗 loader,它就不会用奇怪的方式报复你。** 这些问题不是"被修好了",而是"根本不会产生"。

---

## 5. 安全分析

### 5.1 外人看到什么

| 观察者 | 看到的内容 |
|---|---|
| 宿主上的普通进程 | `/opt/app/lib` 为空或未挂载;ramfs 在私有 namespace 里,`ls` / `cat` 都看不到明文 |
| 磁盘 / `strings` 静态分析 | 永远只有密文(ramfs 不落盘) |
| 进程退出后 | namespace + ramfs 一起蒸发,内存明文消失 |

### 5.2 Tier-1 天花板(不变)

宿主 root 仍然可以:

```bash
nsenter -t <受保护进程 pid> -m   # 进入它的 mount namespace
cat /opt/app/lib/libfoo.so       # 读到明文
```

这与当前方案中 root 可以 `cat /proc/<pid>/fd/N` 是**完全相同的强度** —— Tier 1 的天花板没有降低,也没有提升。要挡本地 root,需要 Tier 2(硬件 TEE),不在本方案范围。

---

## 6. 能退役的现有组件

如果本方案落地,当前一大半复杂度可以删除或简化:

| 组件 | 命运 |
|---|---|
| `exe_shim.c` / `dlopen_shim.c`(LD_PRELOAD) | **大部分可删** —— 不再骗 loader |
| `aarch64_extend_shim.c` 的 popen/符号部分 | **可大幅简化** |
| symlink 目录 + 生命周期 + 清理(`__r_SD` / sweep) | **可删** |
| 逐依赖 RTLD_GLOBAL 预加载 / `__r_NP` | **可删** |
| daemon | **保留但简化**(见 §7.2) |
| memfd / fexecve(exe 这条) | 可保留;lib 这条被 ramfs 取代 |
| 每库随机 memfd 名 | lib 侧不再需要(明文在 ramfs 正常名字下) |

---

## 7. 代价与权衡(诚实评估)

### 7.1 权限要求(主要 gating 因素)

`unshare(CLONE_NEWNS)` 需要 `CAP_SYS_ADMIN`,**除非**包在 user namespace 里(`CLONE_NEWUSER`)且内核允许 unprivileged user namespace。

三种获取方式:

1. **unprivileged user namespace**(零额外部署,但依赖内核配置)
2. 给 stub 文件能力:`setcap cap_sys_admin+ep stub`(一次性)
3. setuid root(**不推荐**,扩大攻击面)

> **可行性判定命令**(见 §9)决定走哪条。

### 7.2 多进程 RAM 共享退化(重要)

当前 memfd + daemon 的精髓:**daemon 解密一次,SCM_RIGHTS 把同一个 memfd 分发给上百个进程,物理内存页共享**。

如果**每个进程树各开各的 ramfs、各自解密一份**:

```
550 库 × N 进程 = RAM 爆炸
```

这是本方案对"100+ 可执行、1000+ 脚本"场景的真实回归。

**解法 —— 共享 namespace**:

- daemon 建**一个** mount namespace + ramfs,解密**一次**
- 受保护进程 `setns()` 进入同一个 namespace 再 exec
- 所有进程共享同一份明文 ramfs → 物理页又共享回来了

代价:复杂度上升;`setns()` 进入他人的 mount namespace 也需要权限(同 §7.1)。

### 7.3 swap 泄漏

tmpfs 可能被换出到磁盘 → **明文落 swap**。规避:

- 用 **ramfs**(无 swap),代价是无大小上限,需自己防 OOM
- 或对解密页 `mlock`,锁住不被换出
- 或确保系统用加密 swap

### 7.4 其他需要处理的细节

- **挂载点覆盖问题**:ramfs 挂在 `/opt/app/lib` 会盖住该目录原有内容。密文要么放在另一个目录(`/opt/app/lib_enc`),要么在挂载前先把密文 fd 全部打开
- **Python 1000+ 脚本**:启动器需在 exec Python 前建好 namespace;之前做的 `.pth` 自动激活机制在 namespace 内仍可用(或者 Python 直接从 ramfs 正常 ctypes 加载)
- **/proc 自省**:进程内 `/proc/self/maps` 会显示 `/opt/app/lib/libfoo.so` 的正常路径(比 memfd 的 `memfd:xxx (deleted)` 更"正常",但也更易读 —— 对 Tier 1 无影响)

---

## 8. 与当前 memfd 方案对比

| 维度 | memfd 方案(现状) | namespace + ramfs(本方案) |
|---|---|---|
| 解密内容位置 | memfd(`/proc/self/fd/N`) | ramfs 里的正常路径 |
| glibc 加载方式 | 被骗(LD_PRELOAD + symlink) | **100% 标准** |
| 符号 / RPATH / `__r_NP` / 冲突 | **无穷尽** | **全部消失** |
| 权限需求 | **零** | namespace 权限(user-ns / setcap) |
| 多进程 RAM 共享 | ✅ daemon + SCM_RIGHTS | 需 setns 共享 namespace 才有 |
| 安全强度 | Tier 1 | Tier 1(相同) |
| 代码复杂度 | 高(shim + symlink + 预加载) | **低**(标准加载) |
| swap 泄漏风险 | 无(memfd 不 swap) | 有(用 ramfs / mlock 规避) |

**取舍本质**:

> memfd 方案用"零权限"换"符号地狱";namespace 方案用"需要 namespace 权限"换"符号地狱清零"。

---

## 9. 可行性判定(动手前必做)

整个方案是否可行,取决于**下位机能否拿到 mount namespace 权限**。先跑:

```bash
# 看 unprivileged user namespace 是否开启
cat /proc/sys/kernel/unprivileged_userns_clone   2>/dev/null   # Debian 系
cat /proc/sys/user/max_user_namespaces                          # 通用,需 > 0

# 直接实测(最权威)
unshare -Urm true && echo "user-ns OK,本方案可行" \
                  || echo "user-ns 被禁,需 setcap 或放弃"
```

判定结果:

- **`unshare -Urm true` 成功** → 本方案可行,走 user-ns 路径,零额外权限部署
- **失败,但可 `setcap`** → 给 stub `cap_sys_admin+ep`,走 CAP_SYS_ADMIN 路径
- **两者都不行(纯零权限硬约束)** → 本方案不可行,留在 memfd + 缩小加密范围

---

## 10. 实施路线图(若可行)

分阶段,每阶段独立可验证:

1. **PoC(1-2 天)**:手写一个最小启动器,`unshare` → mount ramfs → 解密一个库 → exec 一个 demo 程序,确认 glibc 正常加载、符号正常解析
2. **单进程完整版(3-5 天)**:stub 集成 namespace 流程,处理挂载覆盖、密文目录布局、错误回退到 memfd
3. **多进程共享 namespace(1 周)**:daemon 建共享 namespace + ramfs,受保护进程 `setns` 进入,验证 RAM 共享恢复
4. **退役旧机制(逐步)**:确认稳定后,删除 LD_PRELOAD shim / symlink / `__r_NP` 等
5. **回归测试**:用现有 `tests/` 里的隐式依赖、符号冲突、reload 等 case 验证全部转为标准加载后仍通过

---

## 11. 开放问题(待验证)

- [ ] 下位机 user-ns / setcap 可行性(§9)—— **第一优先**
- [ ] 多进程共享 namespace 的 setns 权限是否在目标环境可用
- [ ] ramfs OOM 风险评估(总解密体积 vs 可用 RAM)
- [ ] Python 1000+ 脚本在 namespace 内的启动开销
- [ ] 业务软件是否有依赖"看到磁盘上原始库路径"的逻辑(签名校验、.debug 文件查找等,参考 CLAUDE.md 已知问题)
- [ ] popen / system / fork+exec 子进程是否需要继承 namespace(默认继承,但要确认行为)

---

## 12. 结论

本方案是**同为 Tier 1、但顺着动态链接器而非对抗它**的实现。它用"需要 namespace 权限"这一个代价,换来"符号解析地狱整类问题消失 + 代码复杂度大幅下降"。

**是否可行完全取决于 §9 的权限判定。** 在跑出 `unshare -Urm true` 的结果之前,不应进入实施阶段。
