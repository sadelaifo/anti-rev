# 源码语义审查交接文档 — C++ 进程内存增长

> **用途**:把已经完成的内存现场诊断结论交接给**有源码访问权限的审查方**(内部 LLM 或人工 reviewer)。读者不需要看本仓库的其他文档,本文自包含。
> **来源**:配套 skill `.claude/skills/cpp-memleak/SKILL.md`(方法论);完整诊断过程见 `docs/cpp_aarch64_memleak_investigation.md`(本文是它的精简结论版)。
> **范围**:本文档**仅做 Phase 3(源码语义审查)交接**。Phase 0-2 已完成,Phase 4 已做完两组独立验证,结论稳定。

---

## 1. 现场基线(已固化,无需重新诊断)

| 项 | 值 |
|---|---|
| 平台 | Linux aarch64,GPB 板(嵌入式服务器) |
| 程序 | C++ 业务进程(长跑) |
| Allocator | **glibc 默认 ptmalloc**(已确认无 LD_PRELOAD、无 MALLOC_* env、无 jemalloc/tcmalloc) |
| CPU | 8(决定 ptmalloc arena 上限 = 64) |
| 线程数 | 59(稳定,任意时点观测都是 59) |
| 当前 RSS | ~21.6 GB |
| 增长速率 | **2.7 MB/min ≈ 162 MB/h ≈ 3.88 GB/天**(稳态线性) |
| Live 业务数据量 | ~21.0 GB(`system - rest - fast`)|

---

## 2. 已经排除的方向(不要再去查)

| 方向 | 排除证据 |
|---|---|
| 线程泄漏 / thread_local stack 增长 | 线程数 59 长期稳定不变 |
| 自定义 allocator(tcmalloc / jemalloc / mimalloc) | `/proc/PID/environ` 无 LD_PRELOAD,无相关 env |
| ptmalloc 碎片化 | free 池(`<total rest>`)长期稳定 469 MB,不随 RSS 增长 |
| ptmalloc 不归还内存(arena 累积) | T0→T1 期间 Δrest = -0.01 MB,新拿的页 100% 是 live 数据 |
| mmap 大对象单次累积 | 无 > 64 MB 新增 anon 段;`<total mmap>` 稳定 665 MB |
| 共享内存 / 文件 page cache | Pss ≈ Rss,内存几乎完全私有 |
| 大 buffer / 大对象池 | 平均 free chunk ~512 B,累积单元是**小对象** |
| 第三方 allocator hook | 无 |

→ 上述方向的代码改动**不会解决问题**,审查时可以快速跳过。

---

## 3. 嫌疑代码必须满足的约束(Phase 1 输出)

> ### ⚠ 2026-06-04 修订:原画像已被 Exp-A 推翻
>
> 跑了 `docs/cpp_memleak_constraint_experiments.md` 中的 Exp-A 后:
>
> - **per-arena `<system current>` 分布 max/avg = 45.9×**
> - 大段 ΔRSS = 0(仍是许多小对象累积形态)
>
> 这意味着**单个 arena 独占 RSS 的 70%+(约 15-16 GB)**,其余 58 个 arena 共担 ~5-6 GB。**"所有 worker 都路过的稳态业务热路径"这条约束完全失效** — 不是 59 个线程均匀贡献,**是某 1 个线程独占累积**。
>
> ### 修订后画像
>
> **某个特定线程**(主线程 arena 0,或某 thread arena N>0)在持续向 long-lived 容器推入小对象(~512 B 量级),~每秒 90 次,合计 ~15-16 GB。**其他 58 个线程基本无辜**,不必审查。
>
> ### 还需要 Exp-F 进一步确认
>
> 待执行 `cpp_memleak_constraint_experiments.md` **Round 2 — Exp-F**(arena → thread 映射)。Exp-F 给出 tid 和它的 entry function 后,本 §3 会进一步细化为:**"thread tid=X (entry function = Y) 在调用链上某处持续 alloc 小对象不释放,审查范围 = 该 tid 调用链触及的代码,而非全代码库"**。
>
> ### 在 Exp-F 完成前,审查方应:
>
> - **跳过**本 §3 下方原约束中"所有 worker 都路过的共享逻辑"那条
> - **重点关注** §3 下方"long-lived 容器形态"(static / Singleton / Manager / 全局)中**可能被某单一线程独占**的那些
> - 优先考虑:Singleton 主线程持有的容器、专职 worker 线程(logging thread、metric thread、background thread、gc thread)独占的容器
>
> ### 下方原始约束表(保留作上下文)



每条约束都是对源码的**过滤器**。嫌疑代码必须**同时满足**所有约束。

| 诊断事实 | 推导出的代码约束 |
|---|---|
| Live 数据 ~21 GB,利用率 97.7% | 嫌疑代码包含 **long-lived 容器或持久持有结构**(static 成员、namespace 全局、Singleton/Manager 成员、长寿对象的成员、thread_local) |
| 平均 free chunk ~512 B,~91.7 万个 | 累积的**单个对象**在 **几十~几百字节量级**:`std::string`、节点式容器的 node、shared_ptr control block、小 struct。**排除大 buffer 类**(单对象 ≥ 数 KB) |
| 2.7 MB/min ÷ 512 B ≈ **每秒约 90 次分配不释放** | 触发频率在**每秒数十~数百次**,即**稳态业务热路径**(消息分发、事件循环、轮询、定时器)。**排除冷路径**(配置加载、错误处理、初始化、shutdown) |
| 59 线程都贡献,arena 数 ≈ 线程数 | leak 在 **所有 worker 线程都路过的共享逻辑** 里,不是个别 worker 独有的代码分支 |
| 涨势稳态、无突变 | **不是事件触发型**(reconnect 风暴、配置 reload、burst 入流);**是稳定业务流量自身**在累积 |
| Pss ≈ Rss | 与共享内存 / mmap 公共文件 / page cache 无关 |

**合并约束 → 嫌疑画像(一句话)**:

> **所有 worker 线程都路过的稳态业务热路径里,有一个或多个 long-lived 容器(static / Singleton 成员 / Manager 成员 / thread_local),被 ~每秒几十到几百次推入小对象(~512 B 量级),没有匹配的清理路径,或清理条件永远不触发。**

---

## 4. C++ 业务里最常见的 6 种 leak 模式(优先按此分类)

每条给出**画像匹配度**和**源码语义识别要点**。审查时按**匹配度**从高到低排查。

### Pattern A: `unordered_map / map<Key, Value>` 单调增长
- **匹配画像**:long-lived ✓,小到中等对象 ✓,稳态写入 ✓ — **本 case 最优先**
- **识别**:类成员或全局位置的 `std::(unordered_)?map<...>`,其 `insert` / `emplace` / `operator[]` / `try_emplace` 在 dispatch / handler / loop 里被调,但找不到对应频率的 `erase` / `clear`;或 `erase` 的触发条件是"很少发生"的边界(如 "只在 disconnect 时清"、"只在 evict 满时清,但 cap 太大永远不满")
- **典型实例**:metric 聚合 by key;session/connection map;cache 无 TTL;请求历史按 id 索引
- **快速验证**(如能加诊断代码):打印那个 map 的 `.size()`,看是否单调增

### Pattern B: `vector<T*>` 装裸指针,析构时不 delete
- **匹配画像**:long-lived ✓,小对象 ✓,稳态 ✓
- **识别**:long-lived 的 `std::vector<T*> v`,有 `v.push_back(new T(...))` 在 hot path;容器析构时**只析构 vector 自身**,不 delete 元素;或元素被替换时没 delete 旧的
- **典型实例**:工厂 / registry 模式遗留的 C 风格代码;迁移到 C++ 一半的库
- **快速验证**:看 `vector::size()` 单调增,且内部对象不再被读

### Pattern C: `shared_ptr` 循环引用
- **匹配画像**:long-lived ✓,大量 small control block(~16-32 B)✓,稳态 ✓
- **识别**:`shared_ptr<A>` 持有 `B`,`B` 又通过成员 / lambda capture / callback 持有 `shared_ptr<A>`;两边的 `use_count` 永远不归零
- **典型实例**:Session 持有 `shared_ptr<Connection>`,Connection 通过 callback / observer 持有 `shared_ptr<Session>`
- **修法**:把其中一边改成 `weak_ptr`
- **快速验证**:在 A 或 B 析构里打日志,看是否被调到

### Pattern D: Callback / Observer / Subscriber 注册没注销
- **匹配画像**:long-lived(broker / event_bus 是长寿)✓,closure 小对象 ✓,稳态 ✓
- **识别**:`subscribe / register / addListener / on(...) / connect(...)` 在 hot path 被调,但对端的 `unsubscribe / remove / off / disconnect` 找不到或仅在罕见路径(如 destructor)被调;或注册时返回的 token / handle 被丢弃,无法注销
- **典型实例**:event bus / signal-slot;Boost.Signals2 connection 没保存;Qt signal/slot 跨对象 connect 没 disconnect
- **快速验证**:打印 broker / dispatcher 的订阅者数

### Pattern E: `thread_local` 容器
- **匹配画像**:**完美匹配** "59 线程平均贡献" 这条约束(每线程独立累积,合起来均匀)
- **识别**:`thread_local std::xxx<...>` 在 .h / .cpp 里;线程从生到死期间它没有 reset / clear 路径
- **典型实例**:线程局部统计 buffer;每线程缓存
- **快速验证**:在不同线程上加 `pthread_getspecific` 等价物对比

### Pattern F: 第三方库的已知累积点
| 库 | 已知累积点 |
|---|---|
| protobuf | `google::protobuf::Arena` 没 Reset;反复 `set_*` 同一字段不 release 旧;`MessageFactory` 缓存 |
| libcurl | `CURL` handle 没 `curl_easy_cleanup`;multi handle 没 `curl_multi_cleanup`;`CURLOPT_VERBOSE` debug callback 持有 |
| OpenSSL | `SSL_CTX` session cache 默认无上限;`X509` 链没 free;`ERR_*` 队列未清 |
| log4cxx / spdlog | 异步 logger 的 backlog buffer 是否归还;rolling appender 句柄 |
| RapidJSON / nlohmann::json | 反复 `Parse` 不 `Clear` / 不重用 Document |
| Boost.Asio | `io_context::work` 长期持有;timer 没 cancel;strand 持有 lambda capture |
| zmq / nanomsg | socket option / monitor pair 未清 |

→ 列出本进程引入的第三方库,**逐个评估**它的"长期持有结构"是否有清理路径。

---

## 5. 源码审查执行方法(Phase 3)

> **核心原则**:不做 grep 式模式匹配,做**语义分析**。即:理解每段代码的**生命周期、调用频率、触发条件、对称性**,然后判断是否满足 §3 的画像约束。

### 5.1 找"所有 worker 都路过的稳态热路径"
- 主事件循环 / 消息分发 / 协程调度 的 dispatch 函数
- worker thread 的 `run()` / `loop()` 入口
- 中间件 / 拦截器 / handler chain 的入口
- 协议解析器的 main entry
- RPC / RESTful server 的 request handler
- 定时器 / 心跳 / 轮询 / polling 入口

每条热路径**沿着调用链往下追**,记录路径上**每一次对 long-lived 容器的写入**。

### 5.2 列举所有 long-lived 容器
按形态系统枚举(不要漏类):

| 形态 | 怎么识别 |
|---|---|
| 类的 `static` 成员变量 | 类定义里 `static T member`,且 T 是容器 / 智能指针 / 裸指针 / handle 表 |
| namespace-level / .cpp 文件顶部全局 | 非 const 容器变量 |
| Singleton / Manager / Registry 类的实例变量 | 通过 `Foo::instance().container` 访问 |
| 长期存活 manager 的成员 | 在 `main()` 早期 new、shutdown 前不 delete 的对象的成员 |
| `thread_local` 容器 | `thread_local std::xxx<...>` |
| 长期持有的 unique_ptr / shared_ptr 内部的成员 | 持有方是上述任意一种 |

### 5.3 对每个候选容器做"写-清"对称性分析
1. 列出**所有写入站点**:`insert / emplace / emplace_hint / push_back / push_front / operator[] / try_emplace / merge / [] = / set / put / add / register / subscribe`
2. 列出**所有移除站点**:`erase / clear / pop_front / pop_back / extract / reset / swap-with-empty / unregister / unsubscribe / remove / delete-from-it`
3. 评估两侧:
   - **触发频率**(是否在 hot path)
   - **触发条件**(是否常态)
   - **是否在异常路径里漏掉**
4. 估算"未释放速率"= 写入频率 × 单元素字节 − 移除频率 × 单元素字节
5. 与观测到的 **2.7 MB/min ≈ 47 KB/s** 比对:在**一个数量级内**才是强嫌疑

### 5.4 嫌疑排序(产出格式见 §6)
- 强嫌疑:速率估算 ±1 OOM 内 + 符合 §4 某 pattern + 在 §5.1 的热路径上
- 中嫌疑:符合 pattern 但速率难以估算
- 弱嫌疑:符合形态但不在热路径

---

## 6. 期望产出格式(交接给原诊断方)

请按以下表格交回结论,**不要做 grep 式报告**(列文件名 + 关键字命中)。

### 6.1 嫌疑代码登记表

| 排名 | 文件:行 | 嫌疑容器(类型 + 名称) | 命中 pattern (§4) | 在哪个热路径写入 (§5.1) | 写入频率估算 | 单元素字节估算 | 累积速率估算 | 是否在 ±1 OOM 内匹配 47 KB/s | 移除路径是否存在 / 触发率 | 建议修法 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | | |
| 2 | | | | | | | | | | |

### 6.2 每个 Top-N 嫌疑的详细推理(每个 1-2 段)
- 为什么符合 §3 画像约束(逐条对照)
- 为什么命中所选 pattern
- 速率估算的依据(单元素字节 × 调用频率)
- 移除路径为何不触发 / 触发不够频繁
- 建议修法(具体到代码):加 erase / 改 weak_ptr / 加 TTL / 加 size cap / 用 smart pointer / RAII 等

### 6.3 已排除的疑似(避免冗余审查)
- 形态像但不符合画像的容器(写在 hot path 但定时清空 / 不在 long-lived 对象上 / 单对象太大不符合 ~512 B 约束 等)

### 6.4 仍不确定的代码(需更多信息)
- 调用频率估算缺数据
- 涉及第三方库内部行为
- 涉及编译期/模板展开难以判读

---

## 7. 防过拟合提醒(交给审查方)

我们已经确定本 case 落在 ptmalloc + long-lived 小对象容器,但**审查时仍需保持开放**,避免被本文档的具体数字带偏:

- **不要**仅因为某代码"看起来像 leak"就报告;要算速率匹配
- **不要**忽略可能多个 leak **并存**的情况(top-5 列出可能不止一个真嫌疑)
- **不要**默认 Pattern A 一定对;让数据排序
- **如果**在审查过程中发现矛盾(比如所有候选的速率合起来都解释不了 2.7 MB/min),**回报矛盾**,不要硬凑结论
- **如果**发现"看起来无关但确实出现在所有热路径"的可疑代码(比如某个 logging / tracing / metric 切面),**单独列**为可疑面

---

## 8. 验证回路(审查产出修复后)

修复部署后,**用同样的 snapshot diff 法**做验证:

| 修复后预期 | 含义 |
|---|---|
| Δsystem ≈ 0,Δrest ≈ 0 | 完全治愈 |
| Δsystem 显著下降(但 > 0)| 修了其中一个 leak,**可能还有另外的** |
| Δsystem 不变 | 修错地方或修法无效 |

预期判定时长:观察 ≥ 2 小时 snapshot;**绝对不要**只看分钟级 RSS 就下结论,RSS 抖动很大。

---

## 9. 配套文件

- 方法论 skill:`.claude/skills/cpp-memleak/SKILL.md`(语义审查的通用做法,与本 case 解耦)
- 完整诊断过程 + 数据原始记录:`docs/cpp_aarch64_memleak_investigation.md`(留作 forensics 参考)
- **约束收窄实验手册**:`docs/cpp_memleak_constraint_experiments.md`(Exp-A~E,在把本 handoff 交给审查方**之前**跑,可能会修订本文 §3 的约束表)
- 本文:`docs/cpp_memleak_source_review_handoff.md`(给审查方的精简交接)

> 注意:本 handoff §3 的画像是经验先验,**不是数据强制的唯一形态**。强烈建议先按 `cpp_memleak_constraint_experiments.md` 跑一轮 Exp-A/B/D/E(都不重启,~ 30-60 min),再决定 §3 要不要改。原画像至少漏掉了:Alt-1 单大对象、Alt-2 自管理 pool、Alt-3 异步背压、Alt-7 dlopen 累积等替代假说。
