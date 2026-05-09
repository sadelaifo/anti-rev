# `expr_compiler` 整体方案

`tools/expr_compiler.py` 把一个数学表达式字符串编译成可被高频调用的 Python / 机器码函数。本文档讲整体设计、内部流水线、各处针对超长表达式做的兜底，以及 API 用法。

## 一、解决什么问题

- 表达式可能很长（已实测 460 KB / 15000 项可正常编译）→ sympy 解析、CPython 编译、numba JIT 各自的递归限制都会撞上。
- 表达式存在 JSON 里 → 常量、子表达式、变量名分散在不同字段，需要灵活的路径取值。
- JSON 里写的浮点数（如 `0.833333333333`）不能被四舍五入。

## 二、调用入口

两个常用入口 — 取决于一次要编一条还是多条公式：

**单条**：

```python
from expr_compiler import make_expr_func_from_json

f = make_expr_func_from_json(
    "config.json",
    expr_at      = "expr.f1",                 # 公式字符串路径
    constants_at = ["key1", "key2"],          # {name:数字} 字典路径，可多个
    subexprs_at  = "subexprs",                # {name:子公式串} 字典路径
    # params_at 不传 → 自动检测剩余 free symbols，按字母序
)
f(1.5, 220.0)
```

**多条共享常量 / 子表达式**：

```python
from expr_compiler import make_expr_funcs_from_json

funcs = make_expr_funcs_from_json(
    "config.json",
    exprs_at     = "expr",                    # 路径指向 {name: 公式串} 字典
    constants_at = ["key1", "key2"],
    subexprs_at  = "subexprs",
)
funcs["f1"](1.5, 220.0)
funcs["f2"](1.5, 220.0)
```

JSON 只读一次，常量 / 子表达式只合并一次，所有公式在一个 worker 线程里串行编译，比循环调单条版本省开销。每条公式各自自动检测变量；如果想统一签名就传 `params_at` 给所有公式同一份变量列表（每条公式的 free symbols 必须是子集，不用的名字成为占位参数）。

## 三、流水线全图

```
JSON 文件
   │
   │  json.load(parse_float=str)        ← 浮点保持原文，不被 IEEE754 截断
   ▼
{ "expr": {"f1": "..."},
  "key1": {"a":1.0}, "key2": {"b":2.0},
  "subexprs": {"power":"v*i"} }
   │
   │  get_at_path / _merge_dicts_at      ← 主线程，廉价
   ▼
原始公式串 + 合并好的常量 dict + 子表达式 dict
   │
   │  ┌──────────────── 64–256 MB 大栈 worker 线程 ──────────────┐
   │  │  recursionlimit = 1_000_000                               │
   │  │                                                           │
   │  │  _expand_subexprs   ← AST 级 xreplace，循环依赖检测       │
   │  │  _substitute_constants ← 常量编译期内联成数字字面量       │
   │  │  _detect_params      ← 自动取剩余 free symbols（字母序）  │
   │  │                                                           │
   │  │  _compile_pyfunc:                                         │
   │  │     ├─ _sympify_chunked                                   │
   │  │     │     字符串先切顶层 + / -                            │
   │  │     │     每片独立 sympify，再 sp.Add(*pieces)            │
   │  │     │     得到扁平树（深度 ~5，宽度 N）                   │
   │  │     │                                                     │
   │  │     ├─ sp.cse (大表达式时关 'basic' 优化)                 │
   │  │     │                                                     │
   │  │     ├─ _emit_chunked_main                                 │
   │  │     │     长 Add 切成 _s0=...; _s1=...; return _s0+_s1+.. │
   │  │     │     CPython 解析深度从 O(N) 降到 O(√N)              │
   │  │     │                                                     │
   │  │     └─ exec(src) → Python 函数对象                        │
   │  └───────────────────────────────────────────────────────────┘
   │
   │  numba.njit (主线程，让 JIT 缓存归属正确)
   ▼
JIT 编译的可调用对象 f(args) → float
```

## 四、四道递归屏障对应四层防护

| 屏障 | 哪里出问题 | 防护手段 |
|---|---|---|
| ① Python `recursionlimit` 默认 1000 | sympy 树遍历 / CPython AST 构建逐操作符递归一层 | 提到 1_000_000 |
| ② OS 线程 C 栈（Windows 1 MB） | Python 帧每帧 ~1 KB，~1500 帧就 C 栈溢出 | worker 线程申请 256 MB（自适应回退到 128 / 64 / 32 / 16 / 8 MB） |
| ③ sympify 解析超长串 | 单次 sympify 在 N 项串上递归 N 层 | `_sympify_chunked`：先按顶层 +/- 切片，每片单独 sympify，再 `sp.Add(*pieces)` 拼成扁平树 |
| ④ CPython 编译生成的 Python 源码 | `return a+b+c+...` 是左递归 AST | `_emit_chunked_main`：长 Add 切块成多行临时变量赋值，最后 return 累加 |

任意一层不到位都还是会炸，所以**四层缺一不可**。

## 五、JSON 结构约定

字段位置完全自由，全部由 `*_at` 路径参数指定。一个示例：

```json
{
  "expr": {
    "f1": "scale*power - loss + bias + third*v"
  },
  "physics_consts": {
    "k1": 6.5e-5,
    "k2": 0.001
  },
  "calibration_consts": {
    "bias":  12,
    "scale": 0.5,
    "third": 0.833333333333
  },
  "subexprs": {
    "power": "v * i",
    "ohm":   "k1 * v**2",
    "iron":  "k2 * i**2",
    "loss":  "ohm + iron"
  }
}
```

- **常量** — `{name: 数字}`，可分散在多个 key（`constants_at = ["physics_consts", "calibration_consts"]`），合并时**禁止重名**（防止静默覆盖）。
- **子表达式** — `{name: 表达式串}`，可彼此引用，循环依赖会报错（包括自环 `a: a+1` 和 `a→b→a`）。
- **公式** — 单一字符串，可以引用常量、子表达式，剩下的就是变量。
- **变量** — 不需要在 JSON 里列出，自动检测为 free symbols。

路径语法支持点号风格 `"expr.f1"`、元组 `("expr","f1")`、方括号下标 `"schedule[0].value"`。

## 六、表达式语法

`make_expr_func` 支持 Python `eval` 在同字符串上接受的所有写法：

- `+ - * / **` 和括号 `()`
- 一元负号
- 科学计数法（含省略 0 的小数）：`1.5e-3`、`-.5e12`、`-.11111e-1`
- 含数字、下划线的标识符：`var1`、`x_long_name`、`q_2`
- `**` 右结合且优先级高于 `*`：`2**3**2 == 512`、`2*3**2 == 18`

由 `tests/expr_compiler/test_syntax.py` 的 19 个 case 持续验证（全部用 Python 原生 `eval()` 同字符串作为参考值）。

## 七、精度保证

- JSON 用 `parse_float=str` 加载，浮点的原始字符串原样进 sympy。
- `sp.Float("0.833333333333")` 让 sympy 按字符串位数选择内部精度，不会被默认 15 位字符串化截断。
- 写在源代码里的字面量原样保留位数，可超过 IEEE 754 17 位（运行时计算仍受 IEEE 754 限制，但**生成代码里的位数完整**，方便审查、缓存键去重、对账）。

## 八、性能门道

- **CSE**：sympy 自动找重复子项替换为临时变量，对真有重复结构的公式有用；扁平展开后的多项式没什么可省，所以 args > 10k 时直接关掉 `optimizations='basic'` 这一层（O(N²) 行为）。
- **numba JIT**（`jit=True` 默认开）：第一次调用编译几百 ms，`cache=True` 把机器码落盘，下次进程启动直接读。`fastmath=True` 让 LLVM 重排 + FMA，约 2x 提速（不能容忍 NaN/Inf 的话关掉）。
- **纯 Python 后路**：`jit=False` 跳过 numba 依赖，约 10x 慢于 JIT 但可调试，且不依赖 numba 在新平台上的可用性。

## 九、运行时表现

| 表达式规模 | 字符串长度 | 项数 | 首次编译 | **缓存命中** | JIT 后单次调用 |
|---|---|---|---|---|---|
| 中型 | ~5 KB | 几十–上百 | < 0.5s | < 0.02s | ~10–50 ns |
| 大型 | ~150 KB | 5000 | ~3s | < 0.05s | ~50–200 ns |
| 极大 | ~460 KB | 15000 | ~12s | < 0.1s | ~100–500 ns |

编译时间随项数大致线性。运行时单次调用因为最终生成的是 LOAD_FAST + 浮点 ALU 序列，瓶颈是表达式总操作数。

**磁盘缓存** — 编译产物按 `SHA-1(公式 + 常量 + 子表达式)` 落到 `<tempdir>/expr_compiler_gen/_expr_<hash>.py`。同一份 JSON 第二次跑命中缓存时**只剩 exec + numba 缓存查找**，不重做 sympy 任何工作（实测 25–400x 加速，取决于公式大小和 OS 文件缓存状态）。改任何一个输入（公式文本、常量值、子表达式定义）都会改变 hash 自动失效。

**单次 sympify 流水线** — 早期版本走 `_expand_subexprs → str → _substitute_constants → str → sympify → cse` 的 3 次 sympify 链；现在改成一次 sympify 后 AST 层一次 xreplace 同时把 subexprs 和 constants 解析到不动点，**首次编译也快约 3x**。

## 十、API 一览

| 函数 | 用途 |
|---|---|
| `make_expr_func_from_json(...)` | **主入口**，从 JSON 单文件取**一条**公式编译 |
| `make_expr_funcs_from_json(...)` | **批量版**，`exprs_at` 指向 `{name: 公式}` 字典，一次编多条；常量 / 子表达式共享 |
| `make_expr_func(expr_str, params)` | 直接传字符串编译（已有公式串时用） |
| `make_expr_func_cached(...)` | LRU 包装版，重复调用同表达式时直接命中缓存 |
| `make_funcs_from_json(...)` | JSON 顶层就是 `{name: 公式}`、无常量子表达式共存时用 |
| `load_expressions_from_json(...)` | 公式散落在异构 JSON 树里，按谓词函数定位 |
| `get_at_path(data, path)` | 通用路径取值工具 |

## 十一、调试 / 看生成代码

```python
f = make_expr_func_from_json(
    "config.json",
    expr_at      = "expr.f1",
    constants_at = ["physics_consts", "calibration_consts"],
    subexprs_at  = "subexprs",
    debug        = True,    # 打印生成的 Python 源码
)
```

会输出类似：

```
--- generated source ---
def _expr(i, v):
    _s0 = 0.5*i*v - 0.001*i**2 - ... (100 项)
    _s1 = 6.5e-5*v**2 + 0.833333333333*v + ... (100 项)
    ...
    return _s0 + _s1 + _s2 + ...
--- 0 CSE temps, 150 chunk temps ---
```

`CSE temps` 是 sympy 自动抽出的公共子表达式数，`chunk temps` 是 `_emit_chunked_main` 切的中间累加变量数。两个数字加起来反映这条公式编完之后的内部复杂度。

```python
# 也可以查询参数顺序
py_fn = getattr(f, 'py_func', f)        # JIT 时拿底层 Python func
n     = py_fn.__code__.co_argcount
names = py_fn.__code__.co_varnames[:n]
print(f"signature: {py_fn.__name__}({', '.join(names)})")
```

## 十二、回归测试

`tests/expr_compiler/`：

- `run.py` — JSON 路径全套：常量 + 子表达式 + 变量自动检测 + 精度保留（4 组数值参考）
- `test_syntax.py` — 19 个语法 / 优先级 case + 一个 15000 项 / 460 KB 的极限 case 走完整 `make_expr_func_from_json` 流程
- `test_multi.py` — `make_expr_funcs_from_json` 批量编译路径：5 条公式（含不同变量集 / 纯常量公式）共享常量与子表达式，覆盖 `params_at` 统一签名 override
- `test_cache.py` — 内容寻址磁盘缓存 hit / miss / 失效行为及加速比

```bash
python3 tests/expr_compiler/run.py
python3 tests/expr_compiler/test_syntax.py
python3 tests/expr_compiler/test_multi.py
python3 tests/expr_compiler/test_cache.py
```

## 十三、依赖

```bash
pip install sympy           # 必装
pip install numba           # 可选，jit=True 时需要；不装就 jit=False 跑纯 Python（~10x 慢）
```

## 十四、定位 / 上下文

`tools/expr_compiler.py` 是 antirev 项目里的一个独立通用工具，与 antirev 的运行时（stub、shim、daemon）无关，纯当数学函数 codegen 用。所以测试也独立放在 `tests/expr_compiler/` 下，不进 antirev 的 ctest 套件。
