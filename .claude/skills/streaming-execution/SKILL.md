---
name: streaming-execution
description: 通用的"流式逐单元执行"工作流模式 —— 大集合逐项处理 + 产生大产物文件 + 进度文件 + 可中断恢复。配合任何多步 skill 加载使用(如 anatomy-compare、批量重构、大文档生成),尤其适合小 context 本地模型,因为 LLM 不需要知道自己的 context 大小 —— 默认按这套跑就是最稳的。
---

# streaming-execution

## 这份 skill 解决什么问题

任何"对一个大对象集合做多步处理"的任务,如果 LLM 想"一次性把所有源料装进 context 再处理",会:

1. **小 context 模型直接爆**(truncation 静默,信息丢失)
2. **大 context 模型注意力稀释**,产出质量明显下降
3. **崩溃 / 中断后从头重跑**,几小时的工作白做

这份 skill 提供一套**通用的流式工作流**,把任务拆成"逐单元处理 + 持久化进度",**任何 context 大小的 LLM 都能稳跑、可中断恢复、可审计**。

## 谁该加载这份 skill

**配合下列场景的 skill 一起加载**:

- 走遍代码库做 anatomy / 索引 / 摘要
- 对大量文件做同一种修改(批量重构、风格统一)
- 大文档分段生成(每章独立产出)
- 大量 API endpoint 逐个翻译 / 迁移
- 任何"manifest → 逐项处理 → append 产物 → 中断可恢复"的形态

**不该加载的场景**:

- 任务很小(< 5 个对象),直接做就行
- 对象间强耦合,需要全局视角(流水线反而割裂语义)
- 实时响应任务(查询类、对话类)

## 核心循环

```
1. 建 manifest
   Glob / ls / 任何枚举手段产出待处理对象清单 → _<task>_manifest.txt

2. 建产物文件(空)
   头部声明 + 各 section 占位

3. 建 _progress.md
   列出 manifest 全部对象,初始全部 pending

4. 主循环 —— 每次只处理一个对象
   a. Read _progress.md,取第一个 pending 对象
   b. 用 Read offset+limit / Grep 取该对象的源料(只读必要部分)
   c. 用 Grep 取产物文件的相关 section(不要 Read 整文件)
   d. 计算追加内容
   e. 用 Edit append 到产物
   f. Update _progress.md(该对象标 done)
   g. 显式释放 context(下一轮循环就是新的 Read,自然挤掉旧内容)

5. 全部 done 后(可选)
   cleanup pass:去重、重排、最终格式化
```

## 五条铁律

### 1. 只读"当前需要的最小片段"

- 源文件 > 200 行 → 用 `Read offset/limit` 分段读
- 产物 .md > 50 行 → 用 `Grep` 锁定目标 section,**不要 Read 整文件**
- 永远不 Read 完整源码树

### 2. Append-only,不要重写

- 产物文件用 `Edit` append 一段,**不要 Write 整个文件**(否则要先 Read 整文件,context 爆)
- 一段写完立刻落盘,不在 context 里累积多个待写片段

### 3. `_progress.md` 是状态机的唯一真源

格式:

```
task: <任务名,例如 anatomy-compare Phase 1>
total: 47
done: 24
done_list:
  - file_a.py
  - file_b.py
  ...
pending:
  - file_x.py
  - file_y.py
  ...
last_updated: <ISO 时间戳>
```

- 中断 / 重启:LLM 先 `Read _progress.md`,从 `pending` 第一项继续
- **没记录在 `_progress.md` 的进度,就当没做** —— 防止"我以为我做了但其实丢了"

### 4. 不要批量"先全部 Read 再处理"

- ❌ 反模式:`Read file1 → Read file2 → ... → Read fileN → 处理`(context 爆)
- ✅ 正模式:`for each file: Read → process → Write → 释放 → next`

### 5. 物理上"释放 context"

LLM 没有真正的 forget,但**每次新的 `Read` 进入新内容,自然挤掉旧内容的注意力**。所以:

- 不要在循环里"保留"上一轮的源料
- 每个新对象都从 `_progress.md` 重新拿,从源码重新 Read
- 把 working set 在每一轮物理上重置

## 极端情况 —— 连流式都吃紧时(< 32K context)

- `_manifest.txt` 只列 path,不带额外元数据(尽量短)
- 产物的 section 划分尽量细(便于 Grep 局部读)
- 按"对象优先级"先做最重要的 N 个,其他归 `_deferred.md`,跑完一轮再回头看
- 必要时把单个对象再切成子对象(比如一个大类的方法分批处理)

## 关键反模式(LLM 容易犯)

- **"我先把 manifest 全读到内存再处理"** → manifest 大了就爆。永远只取下一个 pending
- **"我把 a_anatomy.md 整份 Read 出来对照"** → 早期内容会挤掉。永远 Grep 出当前 section
- **"我处理完一个先放着,处理完几个一起写"** → 中间崩了全丢。一个就 commit 一次
- **"我心算 context 够,先批量 Read 5 个"** → LLM 不知道自己 context 多大,**不要赌**

## 怎么跟其他 skill 配合

加载顺序:**先 streaming-execution,再业务 skill**。

业务 skill(如 anatomy-compare)在它每个阶段引用 streaming-execution 的核心循环 —— "按 streaming-execution 的核心循环处理本阶段 manifest"。

业务 skill 负责"做什么、产物长什么样、约束是什么";streaming-execution 负责"怎么稳定可靠地跑完"。**两层正交,互不污染**。
