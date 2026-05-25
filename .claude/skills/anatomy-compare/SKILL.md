---
name: anatomy-compare
description: 在两份代码库(典型场景:Python 应用 A 迁移到 C++ 引擎 B)之间产出多层结构化对比 —— 项目 anatomy + 维度对齐 + 按能力划分的函数级业务逻辑 diff。适用于"基础能力 / 业务"边界不清晰、纯函数级对比会丢架构信息、纯架构 anatomy 又看不到行为细节的场景。
---

# anatomy-compare

## 用途与设计前提

为代码迁移规划产出多层结构化对比报告。设计前提:

- A 通常是较老 / 较小 / 应用层一侧(常为 Python)
- B 通常是较新 / 较广 / 引擎层一侧(常为 C++),已实现 A 的一部分能力
- **"engine vs business" 的边界是 emergent 的,不是事先拍出来的** —— 所以本 skill **不做这种分类**
- 跨语言 / 跨架构,**纯函数级对比丢架构,纯 anatomy 丢行为细节** —— 所以分层

## 调用方式

```
/anatomy-compare <A 项目路径> <B 项目路径>
```

如果用户没把两个路径都给齐,**先问清楚再开工**,不要假设默认值。

## 产物

全部写到 `./anatomy_compare_out/`(不存在则创建):

```
a_anatomy.md                       — A 的独立结构化描述
b_anatomy.md                       — B 的独立结构化描述(不准引用 A)
comparison.md                      — 按维度对齐的横向对照
function_logic_cap_<N>_<slug>.md   — 每个能力一份,函数级业务逻辑 diff
```

每份产物的**头部**必须写"本文不做的事"声明(见末尾"显式不做的事"段)。

---

## 配合建议:加载 streaming-execution

本 skill 只关注**比对业务本身**(四阶段 / 11 维度 / 五档分类 / Phase 4 模板)。

"怎么稳定地跑完这么大一摊活" 是**正交的关注点**,抽到了另一份通用 skill `streaming-execution` 里 —— manifest + per-unit + append + `_progress.md` + 可中断恢复。

**强烈建议两份一起加载**,尤其是:

- 小 context 模型(< 100K) → **必须**
- 大 ctx 模型也建议加载,获得 crash-safe 和单步可审计

加载顺序:**先 streaming-execution,再 anatomy-compare**。

下面四个 Phase 里都会说 "按 streaming-execution 的核心循环跑某某 manifest" —— 那些细节都在 streaming-execution 那份里。如果没加载它,LLM 自己也要按"逐单元 + 追加 + 进度文件"的方式走,不要一次性把 A 或 B 全装 context。

---

## 四阶段工作流(必须按序)

### Phase 1 — 构建 A 的 anatomy(独立)

**按 streaming-execution 的核心循环跑**:`Glob` 出 A 的源文件清单 → `_phase1_manifest.txt` → 每次循环只处理一个文件 → 追加到 `a_anatomy.md` 对应维度 section → 更新 `_progress.md`。

沿下列 **11 个维度** 逐项写 `a_anatomy.md`(各维度的 section 在第一个文件处理时初始化,后续文件**追加**到对应 section):

1. **项目目的** — 一句话定位 + 一段展开
2. **入口点** — 怎么被调用(CLI / 库 / 守护进程 / 服务 / ...)
3. **顶层能力清单**(5-30 条粗粒度能力)
4. **架构分层** — 目录 / 模块切分 + 依赖方向
5. **核心抽象** — 承载模型的 class / type / interface
6. **数据流** — 主要数据怎么流过系统、怎么变形
7. **外部依赖** — 第三方库、系统接口、文件、网络
8. **扩展机制** — 怎么加新行为(插件、注册、回调、配置)
9. **配置体系** — 什么可配,怎么表达
10. **状态 + 生命周期** — stateless / 单进程 / 持久;init → run → shutdown
11. **错误处理风格** — exception / status code / panic / silent

**第 3 项每个能力下,子条目列出实现它的函数 / 文件 + 行号** —— 这些是 Phase 4 的锚点。

#### Phase 1 硬约束(不可违反)

- **每条结论必须带源码证据**(`file:lineStart-lineEnd`)。无证据 → 不写
- 用 Read / Grep / Glob **亲自读源码**。**不要照搬 README** —— README 经常过时或漂亮话
- 不确定的维度 → 写 `UNCLEAR — [原因]`,**不准猜**
- 任何维度暂无内容也保留 section,标 `N/A — [原因]`,不能整段省略

### Phase 2 — 构建 B 的 anatomy(独立 —— 严禁参考 Phase 1)

同 Phase 1 的流程、维度、格式、证据要求,**同样按 streaming-execution 的核心循环跑**(`_phase2_manifest.txt` + 逐文件追加 `b_anatomy.md`)。

#### Phase 2 关键硬约束(违反则全盘失效)

- **严禁打开 `a_anatomy.md`**
- **严禁让 A 的词汇、概念、结构泄到 B 的描述里**
- **当作 Phase 1 从未发生过来写 Phase 2**

理由:如果用 A 的镜头描述 B,Phase 3 的对照就失真了 ——"B 看起来像 A,但只是因为我描述 B 时一直在想 A"。

### Phase 3 — 维度对齐对照

**按 streaming-execution 的核心循环跑 —— manifest 是 11 维度本身**:每次只对齐一个维度,从 `a_anatomy.md` 和 `b_anatomy.md` 用 `Grep` 抓出该维度的 section,产出该维度的对照内容追加到 `comparison.md`,然后释放 context 进入下一个维度。

**严禁一次 `Read` 整个 anatomy 文件** —— 即使是大 ctx 模型也别这么干,注意力稀释。

产 `comparison.md`,**每个维度一张并排表 / 段落**。

#### 第 3 项(顶层能力)用五档分类

| 标签 | 含义 |
|---|---|
| ✅ HIGH | 双方都有,语义看起来对得上 |
| 🟡 MEDIUM | 双方都有,但语义对齐不完全 / 不确定 |
| 🔴 GAP | A 有,B 没 → **B 待补** |
| ⚪ EXTRA | B 有,A 不用 → 引擎多余能力,跟本次迁移无关 |
| ❓ UNCLEAR | 看了拿不准 → **强制必须有这一档,不准强行配对求"看起来完整"** |

#### Phase 3 硬约束

- 每行至少引一边的 file:line(双方都有 → 各引一处)
- **不准做 "engine / business" 分类** —— planning 的事
- **不准给迁移顺序 / 优先级建议** —— 同上
- **不准只看名字判断语义等价** —— 没读两边函数体的,只能标 MEDIUM / UNCLEAR,**不能标 HIGH**

#### `comparison.md` 末尾必须列 Phase 4 钻深名单

- ✅ HIGH 和 🟡 MEDIUM 的能力 → 钻深(行为差异最容易藏在这)
- 🔴 GAP 的能力 → **只钻 A 那一侧**(产 "B 应该怎么实现" 的 spec)
- ⚪ EXTRA → 不钻
- ❓ UNCLEAR → 钻深以澄清

### Phase 4 — 函数级业务逻辑 diff

**按 streaming-execution 的核心循环跑 —— 严格"一个能力一份文件,一个函数对一次循环"**:

```
for each capability in Phase 3 钻深名单:
    新建 function_logic_cap_<N>_<slug>.md,先写头部声明
    建 _phase4_cap_<N>_manifest.txt: 列出该 capability 的 A/B 函数对清单
    for each function pair:
        Read 两边对应行号范围(用 offset+limit,不读整文件)
        写一段对照(下方模板)→ append 到 .md
        更新 _progress.md
```

**关键**:函数位置从 `a_anatomy.md` / `b_anatomy.md` 的证据 file:line 拿(这就是为什么 Phase 1/2 必须老老实实标行号)。

对 Phase 3 标的每个能力,写一份 `function_logic_cap_<N>_<slug>.md`(`<N>` 从 01 起,`<slug>` 用英文短词,如 `file_encryption`)。

每个函数对(或函数组,1:N、N:M 都允许)用下面模板:

```markdown
## Function pair: A.<fn> ↔ B.<fn>          (gap 时写 "A.fn ↔ —")

### A.<name>(<args>)  (<file>:<lineStart>-<lineEnd>)
- 输入:<类型 + 语义>
- 算法:<高层步骤>
- 边界:<处理 / 不处理什么>
- 错误:<怎么报错>
- 副作用:<改了什么外部状态>

### B.<name>(<args>)  (<file>:<lineStart>-<lineEnd>)
- 同样字段

### Diff summary
- ✅ <等价点>
- ⚠️ <行为差异 + 迁移影响>
- ℹ️ <非行为差异,例如分块大小、内部 buffer 名>

### Migration note
- <具体建议:改 A / 改 B / 加 shim / 可接受>
```

#### Phase 4 硬约束

- **必须真打开两边函数体读完再写**,**严禁仅凭签名 + docstring 推断**
- **每条 ⚠️ 必须配迁移建议** —— 不能只罗列差异不给行动
- **跨语言 idiom 翻译必须显式标出**(常见对应见下表)
- **1:N / N:M 是常态,不准为了凑 1:1 强配**;一段对应关系一节,写清拆合

#### 跨语言 idiom 对照(遇到时显式说明)

| Python | C++ |
|---|---|
| `@property` getter | getter / setter 对 |
| `with ctx:` 上下文管理器 | RAII 类 / `unique_ptr` deleter |
| generator (`yield`) | iterator class / coroutine |
| `__init__` | constructor + 可能的 factory function + RAII |
| `@dataclass` | POD struct + 可能的 `operator==` |
| decorator | wrapper class / macro / template |
| `**kwargs` | overload set / 参数对象 / builder |
| `raise Exception` | `throw` / `Status` 返回值 / 错误码 |

---

## 可选简化模式(用户主动 opt-in)

如果用户在调用时**明确请求简化模式**(例如:"我的模型小,请用简化模式"),或者你自己运行时发现产出反复被打断:

- **11 维度压成 5 个核心**:1 项目目的、3 顶层能力、4 架构分层、5 核心抽象、6 数据流
- **Phase 4 只钻 Phase 3 标 ⚠️ 风险高的 3-5 个函数对**,其他归入 `_deferred_review.md` 待人工 review
- **结构和约束(证据、五档分类、UNCLEAR 允许)保持不变** —— 损失粒度,不损失可信度

**LLM 不准自己判断"该不该简化" —— 没有用户明确请求,默认按全 11 维度跑**。
LLM 也不准基于"我可能 context 不够"自行简化,因为它不知道自己 context 多大。

---

## 各份产物头部必须写的 "本文不做的事" 声明

把下面这段原样放每份产物开头:

```
> 本文档 *不* 做的事:
> - 不证明语义等价(只是静态比对,runtime / 差分测试必须后续补)
> - 不给迁移优先级 / 顺序(planning 的事,不是 comparison 的事)
> - 不做 "engine vs business" 分类(边界 emergent,planning 时决定)
> - 不给性能评估
```

---

## 什么时候 *不* 用这个 skill

- A、B 在同一层、只需简单函数 map → 用更轻的工具
- 你已经完全懂 A、只需规划迁移 → vertical-slice 更快
- A、B 的层级边界明确 → 简单的 primitive-gap 分析就够
- A 极小(< 5 文件、< 1000 行)→ 直接 Read 两边、回答即可,不必走四阶段仪式

---

## 执行时的几条提醒(给 LLM 自己)

- **跑得慢没关系,跑歪了就全废**。每个 Phase 跑完先停下来 self-check:产物里每条都有证据吗?Phase 2 真的没看 Phase 1 吗?
- **不要把"看起来完整"当成目标**。UNCLEAR、N/A、GAP 都是合法且有价值的产出 —— 假装懂、强行配对才是最大的失败
- **能力清单是结构骨架**,Phase 4 的钻深完全依赖它。Phase 1/2 的第 3 维度建得粗、建得错,Phase 4 全跟着废。这部分要多花时间
- **遇到 1:N / N:M、跨语言 idiom 翻译,慢一点写清楚**,不要急着收 —— 这种地方含金量最高,也最容易藏坑
- **流式执行细节看 streaming-execution skill** —— 它定义了 manifest / append / progress / Read offset+limit 等通用模式,不要在 anatomy-compare 里重新发明
