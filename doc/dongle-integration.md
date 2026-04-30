# 加密狗（硬件密钥保护）集成设计

> 状态：**设计稿** —— 等加密狗厂商/型号确定后落实具体 SDK 调用细节
>
> 目标读者：antirev 维护者、负责加密狗对接的开发者、运维

---

## 目录

1. [原理](#1-原理)
2. [技术路线](#2-技术路线)
3. [实现方案：Lib 保护](#3-实现方案lib-保护)
4. [实现方案：Exe 保护](#4-实现方案exe-保护)
5. [Daemon ↔ Dongle 协议](#5-daemon--dongle-协议)
6. [运维场景处理](#6-运维场景处理)
7. [安全分析](#7-安全分析)
8. [性能预算](#8-性能预算)
9. [实施计划](#9-实施计划)

---

## 1. 原理

### 1.1 当前方案的弱点

antirev 现状：AES-256-GCM 主密钥 `K_master` 直接嵌在每个 `.protected` / `.antirev-libd` 文件的 trailer（最后 48 字节）：

```
┌────────────────┬─────────────┬────────────────┐
│  stub binary   │   bundle    │    trailer     │
│  (plaintext)   │ (encrypted) │  ┌──────────┐  │
│                │             │  │offset 8B │  │
│                │             │  │K_master  │  │ ← 致命弱点
│                │             │  │  32B     │  │
│                │             │  │MAGIC 8B  │  │
│                │             │  └──────────┘  │
└────────────────┴─────────────┴────────────────┘
```

任何拿到 `.protected` 文件的人，**两条 shell 命令就能提取出 `K_master`**：
```bash
filesize=$(stat -c %s stub.protected)
dd if=stub.protected bs=1 skip=$((filesize - 40)) count=32 2>/dev/null | xxd
```

整个静态混淆（obfstr）、运行时身份伪装（exe_shim）、symbol 劫持等防御都建立在 `K_master` 不可得的前提上。**`K_master` 一旦泄漏，全军覆没**。

### 1.2 威胁模型

我们要防御的攻击者画像：

| 攻击者类型 | 能力 | 当前防御 | 加密狗后 |
|----------|------|--------|---------|
| 离线静态分析师 | 拿到磁盘 binary，没目标机访问权 | ❌ 直接提 K_master | ✅ 没狗解不了 |
| 远程入侵者 | 临时拿到 root，能拷贝文件 | ❌ 同上 | ✅ 同上 |
| 内部威胁（开发离职） | 拷走源码 + 部署文件 | ❌ 同上 | ✅ 没物理狗白拷 |
| 已 root 目标机的攻击者 | 能 ptrace、读 `/proc/<PID>/mem` | ⚠️ K_master 在内存有窗口 | ⚠️ 见 §7 |
| 物理偷狗 | 拿到加密狗硬件 | N/A | ❌ 完蛋（但成本高、可吊销） |

**核心目标**：把"拿到磁盘文件就能解密"提升到"必须有特定的物理狗 + 特定的 daemon binary"。

### 1.3 Key Wrapping（KEK / DEK）

**双层密钥模型**：

```
                          ┌── KEK (Key Encryption Key) ──┐
                          │   K_master                   │
                          │   - 永远在加密狗内部          │
                          │   - 只用来"加密别的密钥"      │
                          │   - 调用频次极低              │
                          │   - 单次操作只处理 32 字节    │
                          └──────────┬───────────────────┘
                                     │
                              "用 K_master 加密 K_file_i"
                                     │
                          ┌──────────▼───────────────────┐
                          │   wrapped_i = E(K_master, K_file_i)
                          │   存储在文件头部              │
                          │   (32~48 字节，随密文走)      │
                          └──────────────────────────────┘

                          ┌── DEK (Data Encryption Key) ──┐
                          │   K_file_i (每个文件一把)     │
                          │   - 软件持有 / 解密用         │
                          │   - 用来加密整个文件内容       │
                          │   - 调用频次正常（每字节 1 次）│
                          │   - GB/s 级速度（CPU AES 指令）│
                          └──────────────────────────────┘
```

类比：银行卡的钱（数据）用日常钥匙（K_file_i）开。日常钥匙带身上可能掉。但日常钥匙是被主钥匙（K_master）锁在保险柜的副本——**主钥匙永远不离开保险柜**。

### 1.4 信任链

```
   硬件信任根                软件代理层               消费层
┌──────────────┐         ┌──────────────────┐    ┌─────────────────┐
│  加密狗硬件   │ ◄────► │ antirev-libd      │ ──►│ 业务进程         │
│              │  USB    │                   │    │                 │
│  K_master    │ session │  K_file_i (缓存)   │    │ 解密的 memfd     │
│  (永不出狗)  │         │  K_sess (临时)     │    │ (没接触过 key)   │
└──────────────┘         └──────────────────┘    └─────────────────┘
       │                          │                       │
   物理隔离              SO_PEERCRED + UID 限制     UID 隔离
```

每一层只看到**比它低一层**所需要的信息。攻击者必须同时**击破物理 + 软件 + IPC 三道边界**才能拿到 K_master，这是接近"系统级"的成本。

### 1.5 单连接原则

**只有 daemon 进程能和加密狗通信**，由四层强制：

1. **OS 内核**：USB 设备同时只能被一个进程 `open()`（其他进程拿到 EBUSY）
2. **文件权限 + udev**：把设备节点限制到特定 group（`antirev`）
3. **daemon 抢占持有**：启动后永不释放 fd
4. **加密狗内部**：通过签名校验来访者是合法 daemon binary

业务进程 → daemon → 加密狗 是单向（业务永远不直接接触狗）。

---

## 2. 技术路线

### 2.1 阶段划分

```
┌─────────┐       ┌─────────────┐       ┌──────────────┐       ┌──────────────┐
│ Phase 0 │ ────► │  Phase 1    │ ────► │  Phase 2     │ ────► │  Phase 3     │
│ 现状     │       │ Lib wrapping│       │ Exe wrapping │       │ 加固选项      │
└─────────┘       └─────────────┘       └──────────────┘       └──────────────┘
   K_master 嵌    Lib 用 K_file_i,     Stub 用 K_file_exe,    懒解 / 拔狗 /
   binary 尾部    daemon 调狗 unwrap   通过 daemon 调狗       daemon-binding /
                  (lib 安全)            (lib + exe 都安全)     anti-debug
```

每阶段都是**独立可发布**的，业务方可以按价值优先级选实施深度。

### 2.2 阶段详情

| 阶段 | 工程量 | 收益 | 是否需要狗 |
|-----|------|------|---------|
| Phase 1 | 中（~600 行）| Lib 的 K_master 不再上磁盘；80% 价值 | 是 |
| Phase 2 | 中（~400 行）| Exe 也不再有 K_master；100% 价值 | 是 |
| Phase 3 | 大（~1000+ 行）| 加固内存中 plaintext 的暴露窗口 | 是 |

### 2.3 兼容性策略

- 文件格式 magic 从 `ANTREV01` bump 到 `ANTREV02`
- 老 stub 看到 `ANTREV02` → 报"format too new"明确错误
- 新 stub 看到 `ANTREV01` → 报"format too old, please re-pack"
- 同一部署里**不能混合新老格式**（必须整套升级）

---

## 3. 实现方案：Lib 保护

### 3.1 文件格式

**当前加密 lib 格式**：
```
┌─────────┬─────┬─────┬────────────────┐
│ANTREV01 │ iv  │ tag │   ciphertext   │
│  (8B)   │(12B)│(16B)│   (lib size)   │
└─────────┴─────┴─────┴────────────────┘
```

**新格式（key-wrapping 后）**：
```
┌─────────┬───────────────┬─────┬─────┬────────────────┐
│ANTREV02 │  wrapped_dek  │ iv  │ tag │   ciphertext   │
│  (8B)   │   (40B)       │(12B)│(16B)│   (lib size)   │
└─────────┴───────────────┴─────┴─────┴────────────────┘
                ▲
        K_file_i 的密文，
        必须用加密狗 unwrap
```

`wrapped_dek` 长度取决于 KEK 算法：
- AES-KW (RFC 3394): 40 字节（32 + 8 整型）
- AES-GCM 包装: 60 字节（32 + 12 nonce + 16 tag）
- 加密狗厂商专有 wrap: 视 SDK 而定

我们用 **AES-GCM 包装**：和现有 GCM 流程一致，不需要新算法实现。

```
wrapped_dek = K_file_dek_iv (12B) || GCM_encrypt(K_master, K_file_dek_iv, K_file_i) || GCM_tag (16B)
            = 12 + 32 + 16 = 60 字节
```

### 3.2 Pack 阶段流程

`encryptor/antirev-pack.py` 的 `_encrypt_lib_worker` 改造：

```python
def _encrypt_lib_worker(src_path, dst_path, dongle):
    """加密单个 lib，使用 key wrapping。"""
    
    # 1. 生成本文件专属 DEK
    K_file_i = os.urandom(32)
    
    # 2. 软件 AES-GCM 加密 lib 内容（CPU 速度，~1 GB/s）
    iv = os.urandom(12)
    plaintext = src_path.read_bytes()
    ciphertext, tag = aes_gcm_encrypt(K_file_i, iv, plaintext)
    
    # 3. 通过加密狗用 K_master 包装 K_file_i (一次 USB 调用，~10ms)
    wrapped_dek = dongle.wrap(K_file_i)   # 60 字节
    
    # 4. 写入磁盘 (不含 K_master 任何形式)
    with open(dst_path, 'wb') as f:
        f.write(b'ANTREV02')              # magic + version
        f.write(wrapped_dek)               # 60B
        f.write(iv)                        # 12B
        f.write(tag)                       # 16B
        f.write(ciphertext)                # lib 大小
    
    # 5. K_file_i 用完即弃
    explicit_bzero(K_file_i)
    explicit_bzero(plaintext)
    
    return f"[ok] {src_path.name} ({len(ciphertext):,}B)"
```

### 3.3 Runtime 阶段流程（daemon 端）

`stub/stub.c` 的 `decrypt_enc_file` 改造：

```c
/* 解密一个加密 lib 到 memfd，返回 fd。
 * 这个函数只在 daemon 进程里被调用。 */
static int decrypt_enc_file_v2(const char *path) {
    int fd_in = open(path, O_RDONLY);
    if (fd_in < 0) return -1;
    
    /* 1. 读 magic + 校验版本 */
    uint8_t magic[8];
    pread(fd_in, magic, 8, 0);
    if (memcmp(magic, "ANTREV02", 8) != 0) {
        /* 兼容老格式: ANTREV01 → 走老逻辑（K_master 还在 binary 里）*/
        if (memcmp(magic, "ANTREV01", 8) == 0)
            return decrypt_enc_file_v1(path);
        return -1;
    }
    
    /* 2. 读 wrapped_dek + iv + tag */
    uint8_t wrapped_dek[60];
    uint8_t iv[12], tag[16];
    pread(fd_in, wrapped_dek, 60, 8);
    pread(fd_in, iv,          12, 68);
    pread(fd_in, tag,          16, 80);
    
    /* 3. 调狗 unwrap (一次 USB, ~10ms) */
    uint8_t K_file_i[32];
    if (dongle_unwrap(wrapped_dek, 60, K_file_i) != 0) {
        close(fd_in);
        return -1;
    }
    
    /* 4. 软件 AES-GCM 解密 ciphertext (CPU 速度) */
    int memfd = make_memfd(basename(path));
    if (decrypt_to_memfd(fd_in, 96 /* offset */, K_file_i, iv, tag, memfd) != 0) {
        close(fd_in);
        close(memfd);
        explicit_bzero(K_file_i, 32);
        return -1;
    }
    
    /* 5. 立刻抹密钥 */
    explicit_bzero(K_file_i, 32);
    close(fd_in);
    return memfd;
}
```

### 3.4 Daemon 协议变化

客户端 ↔ daemon 的协议**完全不变**：客户端还是 `OP_GET_LIB(name)` → daemon 返回 memfd via SCM_RIGHTS。

**对客户端透明**——客户端不知道也不关心 daemon 的解密机制是什么。

新增的协议是 **daemon ↔ dongle**，详见 §5。

### 3.5 缓存策略

daemon 内部维护 K_file_i 缓存：

```c
struct dek_cache_entry {
    char     name[MAX_NAME + 1];     /* lib 名 */
    int      memfd;                  /* 解密后的 memfd */
    uint8_t  dek[32];                /* K_file_i, 仅在 lazy 模式下持有 */
    int      has_dek;
};
static struct dek_cache_entry g_dek_cache[MAX_FILES];
```

三种模式（运行时配置）：

#### 3.5.1 饿汉模式（启动时全量解）

```
daemon 启动:
  for lib in scan_dir():
    wrapped, iv, tag, ct = parse(lib)
    K_file_i = dongle_unwrap(wrapped)
    plaintext = aes_gcm_decrypt(K_file_i, iv, ct, tag)
    memfd = memfd_create(lib.name)
    write(memfd, plaintext)
    cache[lib.name] = {memfd, dek=zero}   # 立刻抹 dek
    explicit_bzero(K_file_i)
```

- 启动慢（USB N 次 + 软件解密 N 次），运行时 0 USB
- 启动后内存里**没有** K_file_i 明文，只有解密后的 plaintext
- 适合：lib 数量少、启动时间不敏感、运行时安全要求一般

#### 3.5.2 懒汉模式（按需解，**推荐默认**）

```
daemon 启动: 什么都不做
client 请求 libfoo:
  if cache[libfoo].memfd 存在:
    return memfd
  else:
    wrapped, iv, tag, ct = parse(libfoo)
    K_file_i = dongle_unwrap(wrapped)
    plaintext = aes_gcm_decrypt(K_file_i, iv, ct, tag)
    memfd = memfd_create()
    cache[libfoo] = {memfd, dek=zero}
    explicit_bzero(K_file_i)
    return memfd
```

- 启动 0 USB，第一次请求某 lib 时 ~10ms 延迟（隐藏在 dlopen 里）
- 没用到的 lib 永远不解密
- daemon 内存中 plaintext 数量 ≤ 实际用到的 lib 数

#### 3.5.3 极端模式（每次请求都重解，安全偏执）

```
client 请求 libfoo:
  wrapped, iv, tag, ct = parse(libfoo)
  K_file_i = dongle_unwrap(wrapped)
  memfd = memfd_create()
  decrypt_to(K_file_i, iv, ct, tag, memfd)
  explicit_bzero(K_file_i)
  return memfd  # memfd 用完后客户端关
```

- 每次请求 1 次 USB + 1 次软件解密
- daemon 内存里几乎不留明文（memfd 仍然存在但 K_file_i 寿命极短）
- 适合：daemon 经常被 ptrace 检视的场景，不常见

---

## 4. 实现方案：Exe 保护

### 4.1 当前 .protected exe 结构

```
.protected:
┌────────────────┬─────────────────┬────────────────┐
│  stub binary   │   bundle (enc)   │    trailer     │
│  (plaintext)   │   - main exe ct │  ┌──────────┐  │
│                │                  │  │offset 8B │  │
│                │                  │  │K_master  │  │
│                │                  │  │MAGIC 8B  │  │
│                │                  │  └──────────┘  │
└────────────────┴─────────────────┴────────────────┘
```

stub 启动 → 读 trailer → 用 K_master 解 main exe → fexecve。

### 4.2 新格式

```
.protected:
┌────────────────┬─────────────────┬────────────────┐
│  stub binary   │  bundle (enc)   │    trailer     │
│  (plaintext)   │  - main exe ct  │  ┌──────────┐  │
│                │                  │  │offset 8B │  │
│                │                  │  │wrapped_dek│ ← K_file_exe 的密文
│                │                  │  │  60B     │  │
│                │                  │  │MAGIC 8B  │  │
│                │                  │  │"ANTREV02"│  │
│                │                  │  └──────────┘  │
└────────────────┴─────────────────┴────────────────┘
```

trailer 从 `8 + 32 + 8 = 48` 字节变成 `8 + 60 + 8 = 76` 字节。

### 4.3 Stub 启动流程

新 stub 启动时**必须连接 daemon** 才能解密自己（因为 K_master 不在 binary 里）：

```c
/* stub.c main() 的改造 */
int main(int argc, char **argv, char **envp) {
    /* 1. 读自己的 trailer，校验 magic */
    uint8_t magic[8];
    int self = open("/proc/self/exe", O_RDONLY);
    /* ... 读 trailer 末尾 ... */
    if (memcmp(trailer.magic, "ANTREV02", 8) != 0) {
        if (memcmp(trailer.magic, "ANTREV01", 8) == 0) {
            /* 兼容: 老格式还能跑 */
            return main_v1(argc, argv, envp);
        }
        die("not an antirev binary");
    }
    
    /* 2. 找 daemon */
    char daemon_path[4096];
    derive_daemon_path(real_exe_path, daemon_path);
    
    /* 3. 连 daemon (复用现有逻辑) */
    int sd = connect_to_daemon();
    if (sd < 0) {
        sd = spawn_daemon_and_retry(daemon_path);
        if (sd < 0) die("failed to connect to daemon");
    }
    
    /* 4. 让 daemon unwrap 我的 wrapped_dek */
    uint8_t K_file_exe[32];
    if (daemon_unwrap_for_self(sd, trailer.wrapped_dek, K_file_exe) != 0) {
        die("daemon refused to unwrap");
    }
    
    /* 5. 软件解密 main exe 到 memfd (现有逻辑) */
    int main_fd = decrypt_main_exe_with_key(K_file_exe);
    explicit_bzero(K_file_exe, 32);
    
    /* 6. fexecve (现有逻辑) */
    fexecve(main_fd, ...);
}
```

### 4.4 Daemon 端新增 RPC

daemon 协议加一条：

```
struct op_unwrap_req {
    uint8_t  op;             /* OP_UNWRAP = 0x05 */
    uint16_t wrapped_len;    /* = 60 */
    uint8_t  wrapped[60];
};

struct op_unwrap_resp {
    uint8_t  op;             /* OP_UNWRAPPED = 0x86 */
    uint8_t  status;         /* 0 = ok, 1 = wrap invalid, ... */
    uint8_t  dek[32];        /* 仅 status==0 时有效 */
};
```

daemon 处理：

```c
int handle_op_unwrap(int client_fd, const struct op_unwrap_req *req) {
    /* 1. 校验客户端权限 (SO_PEERCRED 同 UID, 已有逻辑) */
    /* 2. 调狗 unwrap */
    uint8_t dek[32];
    if (dongle_unwrap(req->wrapped, req->wrapped_len, dek) != 0) {
        send_status(client_fd, OP_UNWRAPPED, 1);
        return -1;
    }
    /* 3. 通过 socket 发回 dek */
    struct op_unwrap_resp resp = { .op = OP_UNWRAPPED, .status = 0 };
    memcpy(resp.dek, dek, 32);
    send(client_fd, &resp, sizeof(resp), 0);
    /* 4. 立刻抹掉 daemon 这边的 dek 副本 */
    explicit_bzero(dek, 32);
    explicit_bzero(&resp, sizeof(resp));
    return 0;
}
```

### 4.5 Bootstrap 顺序问题（关键）

新方案下：**没有 daemon → 任何 .protected exe 都起不来**（因为它要求 daemon 帮它 unwrap）。

部署时必须保证：
- 系统启动时 daemon 先于业务起来（systemd Order/After）
- 或用 socket-activated daemon（systemd 的 socket activation）：客户端连 socket 时 systemd 自动起 daemon

推荐 **socket activation**：daemon 不需要长期占资源，第一个客户端来时才启动，业务无感知延迟（systemd activation < 100ms）。

---

## 5. Daemon ↔ Dongle 协议

### 5.1 Phase 1: 互证身份（启动时一次）

#### 5.1.1 daemon 验证狗

```
daemon: 生成随机 challenge N (16 字节)
daemon → dongle: AUTH_CHALLENGE(N)
dongle: sig = ECDSA_sign(K_priv_dongle_internal, N)
dongle → daemon: AUTH_RESPONSE(sig)
daemon: verify(K_pub_dongle, N, sig)
        失败 → exit(1)，业务起不来
```

`K_pub_dongle` 是出厂时**烧进 daemon binary** 的 32 字节公钥（嵌在源码 + obfstr 保护）。对应私钥永远在加密狗内部。

#### 5.1.2 狗验证 daemon

```
dongle: 生成 challenge M (16 字节)  
dongle → daemon: AUTH_REQUEST(M)
daemon: sig = ECDSA_sign(K_priv_daemon, M)
daemon → dongle: AUTH_PROOF(sig)
dongle: verify(K_pub_daemon, M, sig)
        失败 → 拒绝后续所有请求
```

`K_priv_daemon` 是出厂时**嵌进 daemon binary** 的私钥（**软件 secret 的最后阵地**——必须用 obfstr + 反 dump 手段保护）。`K_pub_daemon` 烧进狗的固件里。

这一步保证：**就算偷了狗，没有原版 daemon binary 也用不了**。

### 5.2 Phase 2: 会话密钥协商（可选）

防 USB 总线物理嗅探：

```
ECDH 协商:
  daemon: (sk_d, pk_d) ← random
  dongle: (sk_g, pk_g) ← random
  daemon → dongle: pk_d
  dongle → daemon: pk_g
  双方各自:
    K_sess = HKDF(ECDH(sk_x, pk_y))   /* 32 字节 */
```

之后所有 RPC 用 `K_sess` 做对称加密 + GCM 完整性校验，加 nonce 防重放。

**是否需要这步**：取决于威胁模型。如果担心有人在目标机上接 USB logic analyzer 抓总线，需要；否则可省。

### 5.3 Phase 3: Unwrap RPC（运行期主流量）

```
daemon → dongle: UNWRAP_REQ {
    nonce_n: 12B (会话期单调递增)
    encrypted: GCM_encrypt(K_sess, nonce_n, wrapped_dek)
    tag: 16B
}

dongle:
    1. GCM_decrypt → 拿到 wrapped_dek
    2. K_file_i = AES_decrypt(K_master, wrapped_dek)    ← K_master 在芯片内
    3. encrypted_resp = GCM_encrypt(K_sess, nonce_n+1, K_file_i)
    
dongle → daemon: UNWRAP_RESP {
    nonce_n+1: 12B
    encrypted: 32B
    tag: 16B
}

daemon:
    1. GCM_decrypt → 拿到 K_file_i
    2. 用于解密对应的 ciphertext
    3. explicit_bzero(K_file_i)
```

每次 RPC ~32 + 60 + 头部 < 200 字节，USB 一次来回足够，~5-10ms。

### 5.4 Phase 4: Keepalive

每 30 秒一次 PING 防止狗超时断开：

```
daemon → dongle: PING(timestamp)
dongle → daemon: PONG(timestamp)
```

### 5.5 Phase 5: 关闭

```
daemon 退出时:
  daemon → dongle: CLOSE
  dongle: 清空 K_sess, nonce 计数器
  daemon: 关闭 USB handle
```

### 5.6 协议层错误处理

| 错误 | 起因 | 处置 |
|-----|------|------|
| Auth 签名校验失败 | 假狗 / 假 daemon | 立刻断开，daemon exit |
| GCM tag 失败 | 通信被篡改 / 重放 | 断开，重新协商 K_sess |
| Wrap 解出来不合法 | 损坏 wrapped_dek | 返回错误状态，业务感知"该 lib 损坏" |
| 狗超时 | 狗死机或被拔 | 见 §6.4 |
| nonce 越界 | 长期运行重放窗口耗尽 | 重新走 Phase 1+2 |

---

## 6. 运维场景处理

### 6.1 系统启动 / 首次部署

```
boot:
  ↓
systemd 启动 antirev-libd.service (Type=notify)
  ↓
daemon 扫狗 → 找到 → AUTH → 互证 → 进入服务循环
  ↓
通知 systemd "ready"
  ↓
依赖 antirev-libd 的业务 service 开始启动
```

**关键点**：业务的 systemd unit 必须有 `After=antirev-libd.service` + `Requires=antirev-libd.service`。

### 6.2 daemon 启动（业务运行中）

socket activation 模式下，第一个客户端连接触发：

```
client → connect(@antirev_socket)
   ↓
systemd 检测连接 → fork antirev-libd
   ↓
daemon 扫狗 → AUTH → 进入服务
   ↓
client 的 connect 完成，发请求
   ↓
daemon 处理（首请求触发 lib 解密，~50ms 延迟）
```

### 6.3 daemon 重启

可能原因：升级、崩溃、人工 SIGKILL。

```
daemon 死亡:
  ↓
所有缓存的 K_file_i, K_sess, memfd 全部消失
  ↓
正在运行的业务进程: 不受影响
  - 它们已经 mmap 过 memfd 的页
  - kernel 持有页缓存
  - daemon 死后 memfd 被 close 但页还活着
  - 所以业务进程**继续工作**
  ↓
新的 dlopen 请求:
  - 客户端尝试 connect daemon → ECONNREFUSED
  - 触发 spawn_local_daemon (现有逻辑)
  - 新 daemon 启动 → AUTH → 重新 unwrap → 服务
  - 客户端重试 connect 成功
  ↓
新业务进程启动:
  - 同上：拿不到老 daemon → 触发新 daemon → 服务正常
```

### 6.4 加密狗热拔出

**这是最关键的场景**。狗被拔后：

```
USB 设备节点消失:
  ↓
daemon 下一次 read/write → EIO 或 ENODEV
  ↓
daemon 触发"拔狗"应急流程:
  
  ⓐ 立刻抹掉所有缓存 (饿汉模式)
     - explicit_bzero 所有 K_file_i 副本（如果还在内存）
     - munmap + close 所有解密的 memfd
     - 已经在客户端进程里 mmap 的 memfd: 客户端继续持有, 但 daemon 这边失效
  
  ⓑ 拒绝所有新请求
     - 新 OP_GET_LIB → 返回错误 "no dongle"
     - 客户端的 dlopen 失败
  
  ⓒ 等狗回来或退出
     - 守护进程持续监听 udev 事件
     - 或 daemon 直接 exit, 让 systemd 重启
```

**业务进程视角**：
- 已经 dlopen 完的 lib：仍然能用（页在内核）
- 新 dlopen：失败
- 已加载但被 mprotect PROT_NONE 隐藏的 hot 函数（如果用了 Phase 3 加固）：再访问会 SIGSEGV

业务必须有"狗丢了我也能优雅死掉"的设计——通常是检测错误后退出，让监控告警。

### 6.5 加密狗重新插入

```
udev 事件: USB 设备 add
  ↓
daemon 监听 udev (libudev 或 monitor /dev) 检测到
  ↓
daemon 重新 open 设备 → AUTH → 进入服务
  ↓
状态恢复:
  - 缓存全空（之前抹掉了）
  - 新请求按 lazy 模式重建
  - 旧的 K_sess 不复用，重新协商
```

### 6.6 业务进程启停

业务进程启停**完全不影响 daemon 和狗**。daemon 持续运行，狗的 session 不变。每个业务启动只是一次 IPC（连 daemon 拿 memfd），无 USB 交互。

### 6.7 软件升级（antirev 自身）

升级流程：

```
1. 部署新版 antirev-libd, .protected exe (新格式 ANTREV02)
2. 旧 daemon 还在跑 (服务旧业务)
3. systemctl restart antirev-libd
   - 旧 daemon 退出
   - 新 daemon 启动 → AUTH → 接管
4. 旧业务进程: 继续跑（页缓存）
5. 新业务进程: 用新 daemon
```

**问题**：升级期间如果 .protected 业务本身也升级了，新业务用新 daemon 没问题。但**老业务进程引用的内存页是旧 daemon 解出来的**——旧 daemon 死后，那些页没人维护，不会有问题（kernel 持有），但是没法做 madvise 之类。

### 6.8 K_master 升级（密钥轮换）

如果 `K_master` 怀疑泄漏：

```
1. 用厂商工具往狗里写新 K_master_v2（旧的可保留也可销毁）
2. 用新狗（带 K_master_v2）重新 pack 所有 lib
3. 部署新 lib + 新 daemon binary（公钥保持不变，因为用 ECDSA 验签的是 daemon 身份私钥，不是 K_master）
4. 滚动重启 daemon
```

**老格式（K_master_v1 加密）的 lib 可以共存**：daemon 看 wrapped_dek 头部带版本标记，决定用哪把 K_master 解。狗里同时装两把 K_master，dual-version 平滑过渡。

完成全部迁移后，从狗里删除 K_master_v1。

### 6.9 Patch 包发布

只更新部分文件的场景。流程：

```
1. CI 收到改动文件清单 (libfoo.so, libbar.so)
2. 在线接狗的 CI 机器:
   - 给 libfoo, libbar 各生成新 K_file
   - 各自加密 + wrap with K_master (现网用的那把)
   - 输出: libfoo.so.encrypted, libbar.so.encrypted
3. 推 patch 包 (只含两个文件)
4. 现网部署: 替换两个文件
5. daemon 不需要重启:
   - 旧 K_file 缓存失效 (业务还没下次 dlopen)
   - 下次 dlopen 拿到新文件 → 新 wrapped_dek → 新 K_file_i
6. 业务平滑切换
```

**关键约束**：patch 必须用**现网相同的 K_master 加密**。所以**生产 K_master 永远不能换**（除非接受全量升级）。

### 6.10 跨机器部署

每台部署机都需要一个加密狗（同 K_master）。狗的复制：

- 厂商提供"克隆"工具：用一个母狗写多个子狗
- 或厂商发货时按订单数量出狗
- **不能**远程 / 软件复制（K_master 从不出狗，没法拷贝）

成本考虑：每台机器 ¥100~500 的硬件成本，对量产部署是真实成本。

### 6.11 多 arch 部署

x86_64 和 aarch64 的加密 lib **同 K_master**（密钥与 arch 无关）。一个 daemon 可以服务两个 arch 的 lib（两个不同的加密 lib 文件，各自的 wrapped_dek，但都被同一个 K_master 包装）。

部署目录结构：

```
/opt/biz/
├── .antirev-libd-aarch64    # aarch64 daemon
├── .antirev-libd-x86_64     # x86_64 daemon (跨 arch 部署)
├── lib/
│   ├── x86_64/
│   │   └── libfoo.so.encrypted   # 用 K_master wrap
│   └── aarch64/
│       └── libfoo.so.encrypted   # 同样用 K_master wrap (内容不同, K_file_i 不同)
└── bin/
    └── ...
```

每个 daemon 进程只服务自己 arch 的 lib，但是同一把 K_master。

### 6.12 首次发货 / Provisioning

新订单的 provisioning 流程：

```
1. 厂商生成一对新 ECDSA 密钥 (sk_dongle, pk_dongle)
2. 把 sk_dongle 烧进新狗
3. pk_dongle 给 antirev 团队
4. antirev 团队:
   a. 把 pk_dongle 嵌进 daemon binary (源码或编译时)
   b. 编译该客户专版的 daemon
   c. K_priv_daemon 也嵌进去 (这是软件 secret)
5. K_master 注入新狗:
   a. 客户运维或 antirev 团队（看分工）
   b. 用厂商工具把随机 K_master 写进狗
   c. 同时也用同一把 K_master 加密发货的 lib
6. 出货: daemon binary + 加密 lib + 加密狗
7. 客户上电跑通
```

**密钥治理**：每个客户用独立的 K_master 和 ECDSA 密钥对，**不要全客户共用**。一家泄漏不影响其他家。

---

## 7. 安全分析

### 7.1 攻击场景表

| # | 攻击场景 | 当前 (无狗) | 加密狗后 |
|---|---------|----------|--------|
| 1 | 拷走磁盘文件离线分析 | ❌ 30 秒提 K_master 解全部 | ✅ 没狗解不了任何文件 |
| 2 | 内部威胁拷走源码 + 部署 | ❌ 同上 | ✅ K_master 不在源码 / binary |
| 3 | 偷狗（物理） | N/A | ❌ 完蛋（但成本高、可远程吊销） |
| 4 | 偷 daemon binary + 狗 | ❌ 同 #1 | ⚠️ 狗的 daemon 验证拦截，攻击者写假 daemon 没用 |
| 5 | ptrace daemon 抓内存 | ❌ 抓 K_master | ⚠️ 只能抓当前正用的 K_file_i 们（爆炸半径有限） |
| 6 | ptrace 业务进程 | 同等暴露已解密 plaintext | 同左（这部分本来就同等暴露） |
| 7 | 嗅探 USB 总线 | N/A | ⚠️ Phase 2 启用后 K_sess 加密了，挡住被动嗅探 |
| 8 | 假狗（USB 模拟设备） | N/A | ✅ daemon 验签拒绝假狗 |
| 9 | 假 daemon（替换原版）| N/A | ✅ 狗验签拒绝假 daemon |
| 10 | 重放 wrapped_dek 给狗 | N/A | ⚠️ 拿到对应 K_file_i — 若加 daemon-binding 可挡 |
| 11 | DOS 狗（恶意大量 unwrap）| N/A | ⚠️ 加速率限制 |

### 7.2 仍然挡不住的

- **当前进程内存里已解密的 plaintext** —— 这部分需要 Phase 3 流式解密 / mprotect 等手段
- **glibc / 第三方 lib 的字符串** —— 不在我们源码里，不能 obfstr
- **业务自己的字符串** —— 同上，要业务侧用 obfstr
- **导出符号名**（`ANTI_LoadProcess` 等）—— LD_PRELOAD interposition 必需

### 7.3 K_master 灾难恢复

如果发现 K_master 泄漏（怀疑或确认）：

1. **吊销老狗**：物理回收（如果可控）或宣布作废
2. **生成新 K_master**，写入新狗
3. **重 pack 所有受影响业务**
4. **滚动部署**新 lib + 新 daemon
5. **审计**：能确定泄漏多少？哪些版本受影响？

为了支持这种场景：
- 文件格式头里加 K_master 版本号字段（4 字节够用）
- daemon 同时维护多版本 K_master 缓存（狗里也存多版本）

---

## 8. 性能预算

### 8.1 启动开销（lazy 模式，推荐）

```
daemon 启动:
  - USB AUTH 握手:        ~30 ms
  - ECDH 协商 K_sess:     ~20 ms
  - 进入服务循环
  合计:                   ~50 ms
```

### 8.2 首次访问 lib 开销（lazy 模式下）

```
client 第一次 dlopen libfoo:
  - daemon 收到 OP_GET_LIB:   ~0.1 ms
  - 调狗 unwrap:              ~10 ms
  - 软件 AES-GCM 解密 50MB:   ~50 ms
  - 创建 memfd + 写入:         ~5 ms
  - SCM_RIGHTS 发 fd:          ~0.1 ms
  - client mmap:               ~1 ms
  合计:                        ~66 ms
```

vs 当前 (无 wrapping): ~55 ms
**净增 ~10ms**，几乎不可感知。

### 8.3 后续访问开销

```
client 第二次 dlopen libfoo:
  - daemon 收到请求 → cache 命中 → 直接发 memfd
  - 总耗时 < 1ms
```

后续访问完全不碰狗，与当前方案性能一致。

### 8.4 三种模式对比

| 模式 | 启动 USB | 首次访问 USB | daemon 内存中 K_file_i 寿命 |
|------|--------|----------|---------------------|
| 饿汉 | N 次 | 0 次 | 0（启动后立即抹）|
| **懒汉**（推荐）| 0 次 | 1 次 | 直到 daemon 退出 |
| 极端 | 0 次 | 1 次 / 每访问 | 几十毫秒 |

---

## 9. 实施计划

### 9.1 工程量估算

| 模块 | 工作量 | 依赖 |
|-----|------|-----|
| 选型 + 采购加密狗 | 业务决策 | 厂商 SDK 文档 |
| Pack 工具改造 | 3-5 天 | 加密狗 SDK |
| Daemon ↔ Dongle 协议 | 5-7 天 | 同上 |
| Daemon 内部缓存 + 解密改造 | 3-5 天 | — |
| 文件格式 ANTREV02 + 兼容老格式 | 2-3 天 | — |
| Stub 端 daemon 协议扩展 (`OP_UNWRAP`) | 2-3 天 | — |
| systemd unit + socket activation | 1-2 天 | — |
| 拔狗事件处理 | 2-3 天 | libudev |
| 测试用例 | 5-7 天 | mock 狗 |
| 文档 + Provisioning 流程 | 3 天 | — |
| **合计** | **30-45 天** | |

### 9.2 优先级（建议）

**P0（必做）**：
- Pack 改造 + 文件格式 ANTREV02
- Daemon ↔ Dongle 基础协议（AUTH + UNWRAP）
- Daemon 内部缓存（lazy 模式）
- 兼容老 ANTREV01

**P1（很快做）**：
- Exe 端 stub 改造
- Socket activation
- 拔狗事件处理
- 完整 unit / 集成测试

**P2（后续）**：
- ECDH 会话加密 (Phase 2)
- daemon-binding wrapped_dek (防重放)
- K_master 多版本支持
- Phase 3 加固

### 9.3 关键风险

1. **加密狗 SDK 不支持 wrap 操作** → 需要选型阶段验证。问厂商技术支持要 demo 代码确认有"非提取式"加解密 API
2. **K_priv_daemon 软件保密** → 嵌进 binary 终归是软件 secret，攻击者拿到 daemon binary 可以静态分析提取。需要：
   - obfstr 保护
   - 可能需要更激进的代码混淆
   - 或：让 daemon 启动时用一个一次性挑战换取临时身份证书（更复杂）
3. **socket activation 在某些 init 系统下不可用** → 老 sysv 需要降级方案
4. **拔狗后业务 graceful degrade** → 业务自己要有"daemon 死了"的处理

---

## 附录 A：术语表

| 术语 | 含义 |
|-----|-----|
| KEK | Key Encryption Key — 加密"别的密钥"用的密钥（这里是 K_master）|
| DEK | Data Encryption Key — 加密"实际数据"用的密钥（这里是 K_file_i）|
| Wrap / Unwrap | 用 KEK 加密 / 解密 DEK 的操作 |
| K_master | 主密钥，永远在加密狗里 |
| K_file_i | 文件 i 专用的 DEK，软件持有 |
| K_sess | daemon ↔ dongle 会话期对称密钥（ECDH 派生）|
| ECDSA | 椭圆曲线数字签名算法，用于 daemon ↔ dongle 互证身份 |
| SCM_RIGHTS | Linux Unix socket 传 fd 的机制 |
| PEERCRED | Linux 获取 socket 对端 PID/UID 的机制 |
| Lazy / 懒汉模式 | 按需 unwrap，只在 client 请求该 lib 时才调狗 |

## 附录 B：参考资料

- `stub/stub.c:5-15` —— 当前 trailer 格式注释
- `stub/obfstr.h` —— 字符串混淆设计文档
- RFC 3394 —— AES Key Wrap
- NIST SP 800-38F —— Key wrapping 标准
- 加密狗厂商 SDK 文档（待选型后补充）
