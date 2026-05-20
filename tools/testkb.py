#!/usr/bin/env python3
"""
testkb.py — knowledge base over a Python testcase library.

Why this exists
---------------
A testcase repo is more than a pile of `test_*` functions.  The real
domain knowledge ("how to start the software", "how to clean state",
"how to make a sandbox env") lives in the helpers, fixtures, conftest,
and utility modules.  This tool extracts that knowledge into a queryable
index so devs (or an LLM) can find / learn / reuse it.

Three things this tool gives you:

  1. **Query**: "how do I start the service?" -> the relevant helpers,
     ranked, with usage examples pulled from real tests.
  2. **Browse**: helpers grouped by operation (start / stop / init /
     cleanup / wait / verify / config), so a newcomer can see the
     whole "verb library" of the test repo at a glance.
  3. **Reverse lookup**: "who uses fixture X?" / "which tests cover
     function Y?" -> direct answers from the built call graph.

Quick start
-----------
    pip install sentence-transformers numpy   # optional, enables dense retrieval
    python tools/testkb.py build /path/to/tests
    python tools/testkb.py query "how to start the service"
    python tools/testkb.py helpers --tag start
    python tools/testkb.py users start_service
    LLM_URL=http://internal-llm/v1/chat/completions \\
        python tools/testkb.py ask "write a script that starts the service and runs X"

Storage layout (./testkb_index/ by default):
    manifest.json     counts, model name, dim
    chunks.jsonl      one chunk per line, text + metadata
    bm25.pkl          pure-python BM25 index (tokens + params)
    embeddings.npy    dense vectors, only if sentence-transformers was used

Dependencies are progressive:
    stdlib only                 -> works (BM25 + structural retrieval)
    + sentence-transformers     -> dense semantic retrieval (recommended)
    + numpy                     -> needed alongside sentence-transformers
    LLM_URL env var             -> `ask` command (OpenAI-compatible API)
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import pathlib
import pickle
import re
import sys
import warnings
from collections import Counter, defaultdict
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Operation tagging (cheap heuristic; LLM-assisted refinement is a future step)
# ---------------------------------------------------------------------------
NAME_TAGS: Dict[str, Tuple[str, ...]] = {
    "start":   ("start_", "launch_", "boot_", "spawn_", "run_server", "run_service"),
    "stop":    ("stop_", "kill_", "shutdown_", "terminate_", "halt_"),
    "init":    ("init_", "setup_", "prepare_", "create_", "make_", "build_"),
    "cleanup": ("cleanup_", "teardown_", "destroy_", "reset_", "clean_", "purge_"),
    "wait":    ("wait_", "poll_", "until_", "sleep_", "await_"),
    "verify":  ("verify_", "assert_", "check_", "expect_", "validate_", "ensure_"),
    "config":  ("configure_", "apply_config", "set_config", "load_config", "with_config"),
    "mock":    ("mock_", "stub_", "fake_", "patch_"),
}

DOC_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "start":   ("start", "launch", "boot", "启动"),
    "stop":    ("stop", "shutdown", "terminate", "kill", "停止", "关闭"),
    "init":    ("init", "setup", "create", "prepare", "初始化", "创建", "准备"),
    "cleanup": ("cleanup", "teardown", "reset", "clean", "清理", "重置"),
    "wait":    ("wait", "poll", "until", "等待"),
    "verify":  ("verify", "check", "validate", "ensure", "校验", "验证", "检查"),
    "config":  ("configure", "config", "配置"),
    "mock":    ("mock", "stub", "fake", "patch", "模拟", "桩"),
}


def tag_by_name(fn_name: str) -> List[str]:
    n = fn_name.lower()
    tags: List[str] = []
    for tag, prefixes in NAME_TAGS.items():
        if any(n.startswith(p) or ("_" + p) in n for p in prefixes):
            tags.append(tag)
    return tags


def tag_by_doc(doc: str) -> List[str]:
    if not doc:
        return []
    low = doc.lower()
    tags: List[str] = []
    for tag, kws in DOC_KEYWORDS.items():
        if any(kw in low for kw in kws):
            tags.append(tag)
    return tags


# ---------------------------------------------------------------------------
# AST chunk extraction
# ---------------------------------------------------------------------------
SKIP_DIRS = {".venv", "venv", "__pycache__", ".git", ".tox", "node_modules", "build", "dist"}
MAX_BODY_LINES = 200  # cap chunk body size; full source still on disk


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _signature_for(node: ast.AST) -> str:
    args = node.args
    parts: List[str] = []
    pos = [a.arg for a in args.args]
    if args.vararg:
        pos.append("*" + args.vararg.arg)
    pos.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg:
        pos.append("**" + args.kwarg.arg)
    return "(" + ", ".join(pos) + ")"


def _extract_refs(node: ast.AST) -> Set[str]:
    """Symbols this function calls (the SUT — system under test).
    Captures both bare names and dotted attribute chains."""
    refs: Set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name):
                refs.add(f.id)
            elif isinstance(f, ast.Attribute):
                s = _safe_unparse(f)
                if s:
                    refs.add(s)
                elif isinstance(f.value, ast.Name):
                    refs.add(f"{f.value.id}.{f.attr}")
    return refs


def _make_chunk(node, src_lines: List[str], path: pathlib.Path,
                class_name: Optional[str]) -> Dict:
    decorators = [_safe_unparse(d) for d in node.decorator_list]
    deco_text = " ".join(decorators)
    is_fixture = "fixture" in deco_text.lower()
    is_test = node.name.startswith("test_") or (class_name is not None and class_name.startswith("Test"))
    kind = "fixture" if is_fixture else ("test" if is_test else "helper")

    markers = sorted(set(re.findall(r"pytest\.mark\.([A-Za-z_]\w*)", deco_text)))

    doc = ast.get_docstring(node) or ""

    start = (min([d.lineno for d in node.decorator_list] + [node.lineno])) - 1
    end = node.end_lineno or (start + 1)
    loc = end - start
    if loc > MAX_BODY_LINES:
        body = "\n".join(src_lines[start:start + MAX_BODY_LINES]) + "\n# ... (truncated, see source for full body)"
    else:
        body = "\n".join(src_lines[start:end])

    tags = sorted(set(tag_by_name(node.name) + tag_by_doc(doc)))
    refs = _extract_refs(node)
    fixture_deps = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]

    sig = _signature_for(node)
    header_parts = [f"file: {path}"]
    if class_name:
        header_parts.append(f"class: {class_name}")
    header_parts.append(f"func: {node.name}")
    header_parts.append(f"kind: {kind}")
    if tags:
        header_parts.append("ops: " + ",".join(tags))
    if markers:
        header_parts.append("marks: " + ",".join(markers))
    header = "[" + " | ".join(header_parts) + "]"

    text_parts = [header]
    if doc:
        first_line = doc.strip().split("\n")[0]
        text_parts.append(f"doc: {first_line}")
    text_parts.append(f"sig: {node.name}{sig}")
    text_parts.append("")
    text_parts.append(body)
    text = "\n".join(text_parts)

    cid = hashlib.md5(
        f"{path}::{class_name or ''}::{node.name}".encode("utf-8")
    ).hexdigest()

    return {
        "id": cid,
        "text": text,
        "meta": {
            "source": str(path),
            "class": class_name,
            "function": node.name,
            "kind": kind,
            "tags": tags,
            "markers": markers,
            "fixture_deps": fixture_deps,
            "refs": sorted(refs),
            "docstring": doc,
            "signature": sig,
            "loc": loc,
            "lineno": start + 1,
        },
    }


def iter_chunks_in_file(path: pathlib.Path) -> Iterator[Dict]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    # Suppress SyntaxWarning ("invalid escape sequence '\d'" etc.) that
    # the user's test files trigger when they contain non-raw regex
    # strings like "\d+".  Those warnings are about THEIR code, not
    # ours; ast.parse still produces a valid tree, so the chunks are
    # extracted fine — we just shouldn't spam them at our caller.
    # DeprecationWarning is included for older Python versions where
    # the same condition was a DeprecationWarning.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return
    src_lines = src.split("\n")

    def walk(node, class_name: Optional[str] = None):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield _make_chunk(node, src_lines, path, class_name)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                yield from walk(sub, class_name=node.name)

    for top in tree.body:
        yield from walk(top)


def scan_repo(root: pathlib.Path) -> List[Dict]:
    chunks: List[Dict] = []
    seen_files = 0
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        seen_files += 1
        for c in iter_chunks_in_file(p):
            chunks.append(c)
    print(f"  scanned {seen_files} .py files -> {len(chunks)} chunks", file=sys.stderr)
    return chunks


# ---------------------------------------------------------------------------
# Tokenizer (code-aware: also splits snake_case and CamelCase)
# ---------------------------------------------------------------------------
_WORD_RE = re.compile(r"\w+", flags=re.UNICODE)
_CAMEL_RE = re.compile(r"[A-Z][a-z]+|[a-z]+|[A-Z]+(?=[A-Z]|$|\d)|\d+")


def tokenize(text: str) -> List[str]:
    tokens: List[str] = []
    for raw in _WORD_RE.findall(text):
        if not raw:
            continue
        low = raw.lower()
        tokens.append(low)
        # split snake_case
        if "_" in raw:
            for p in raw.split("_"):
                if p and p.lower() != low:
                    tokens.append(p.lower())
        # split CamelCase / mixedCase / runs
        for p in _CAMEL_RE.findall(raw):
            pl = p.lower()
            if pl and pl != low:
                tokens.append(pl)
    return tokens


# ---------------------------------------------------------------------------
# BM25 (pure stdlib, fine for thousands-of-chunks scale)
# ---------------------------------------------------------------------------
class BM25:
    def __init__(self, docs: List[List[str]], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1 = k1
        self.b = b
        self.N = len(docs)
        self.lens = [len(d) for d in docs]
        self.avgdl = (sum(self.lens) / self.N) if self.N else 0.0
        df: Counter = Counter()
        for d in docs:
            for t in set(d):
                df[t] += 1
        self.idf = {
            t: math.log((self.N - c + 0.5) / (c + 0.5) + 1.0)
            for t, c in df.items()
        }
        self.tf: List[Counter] = [Counter(d) for d in docs]

    def score(self, query: List[str], i: int) -> float:
        s = 0.0
        tf = self.tf[i]
        dl = self.lens[i] or 1
        for t in query:
            idf = self.idf.get(t)
            if idf is None:
                continue
            f = tf.get(t, 0)
            if not f:
                continue
            num = f * (self.k1 + 1)
            den = f + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            s += idf * num / den
        return s

    def topk(self, query: List[str], k: int = 30) -> List[Tuple[int, float]]:
        scored: List[Tuple[int, float]] = []
        for i in range(self.N):
            s = self.score(query, i)
            if s > 0:
                scored.append((i, s))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]


# ---------------------------------------------------------------------------
# Optional dense embeddings
# ---------------------------------------------------------------------------
class Embedder:
    def __init__(self, model_name: str = "BAAI/bge-m3"):
        self.model_name = model_name
        self.ok = False
        self.err = ""
        self.model = None
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self.model = SentenceTransformer(model_name)
            self.ok = True
        except Exception as e:
            self.err = f"{type(e).__name__}: {e}"

    def encode(self, texts, **kw):
        return self.model.encode(texts, **kw)


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------
class Index:
    def __init__(self, chunks: List[Dict], embedder: Optional[Embedder] = None,
                 model_name: Optional[str] = None):
        self.chunks = chunks
        self.by_id: Dict[str, Dict] = {c["id"]: c for c in chunks}
        self.model_name = model_name or (embedder.model_name if embedder and embedder.ok else None)
        self.embedder = embedder

        # reverse callgraph: function name -> chunk ids that call it
        self.called_by: Dict[str, List[str]] = defaultdict(list)
        for c in chunks:
            for ref in c["meta"]["refs"]:
                fn = ref.rsplit(".", 1)[-1]
                self.called_by[fn].append(c["id"])

        # bm25
        self.tokens: List[List[str]] = [tokenize(c["text"]) for c in chunks]
        self.bm25 = BM25(self.tokens)

        # dense (optional)
        self.vecs = None
        if embedder and embedder.ok and chunks:
            try:
                import numpy as np  # type: ignore
                print(f"  encoding {len(chunks)} chunks with {embedder.model_name}...", file=sys.stderr)
                self.vecs = embedder.encode(
                    [c["text"] for c in chunks],
                    batch_size=32, show_progress_bar=True,
                    convert_to_numpy=True, normalize_embeddings=True,
                )
            except Exception as e:
                print(f"  warning: dense embedding failed ({e}); falling back to BM25-only", file=sys.stderr)
                self.vecs = None

    # ----- query -----

    def search(self, query: str, k: int = 8,
               filters: Optional[Dict] = None) -> List[Dict]:
        qtok = tokenize(query)
        cand_pool = k * 5

        bm_ranked = [i for i, _ in self.bm25.topk(qtok, k=cand_pool)]
        dense_ranked: List[int] = []
        if self.vecs is not None:
            try:
                import numpy as np  # type: ignore
                qv = self.embedder.encode([query], normalize_embeddings=True)[0]
                sims = self.vecs @ qv
                dense_ranked = list(np.argsort(-sims)[:cand_pool])
                dense_ranked = [int(i) for i in dense_ranked]
            except Exception:
                dense_ranked = []

        fused = _rrf([bm_ranked, dense_ranked], k_const=60)

        keep_set: Optional[Set[int]] = None
        if filters:
            keep_set = {i for i in range(len(self.chunks)) if self._match(i, filters)}
            fused = [i for i in fused if i in keep_set]

        return [self.chunks[i] for i in fused[:k]]

    def _match(self, i: int, filters: Dict) -> bool:
        m = self.chunks[i]["meta"]
        for key, want in filters.items():
            got = m.get(key)
            if isinstance(want, (list, tuple, set)):
                wset = set(want)
                if isinstance(got, list):
                    if not (wset & set(got)):
                        return False
                else:
                    if got not in wset:
                        return False
            else:
                if isinstance(got, list):
                    if want not in got:
                        return False
                else:
                    if got != want:
                        return False
        return True

    # ----- persistence -----

    def save(self, out_dir: str) -> None:
        out = pathlib.Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "chunks.jsonl", "w", encoding="utf-8") as f:
            for c in self.chunks:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        with open(out / "bm25.pkl", "wb") as f:
            pickle.dump(
                {"tokens": self.tokens, "k1": self.bm25.k1, "b": self.bm25.b},
                f, protocol=pickle.HIGHEST_PROTOCOL,
            )
        manifest = {
            "count": len(self.chunks),
            "has_dense": self.vecs is not None,
            "dim": int(self.vecs.shape[1]) if self.vecs is not None else None,
            "model": self.model_name if self.vecs is not None else None,
        }
        if self.vecs is not None:
            import numpy as np  # type: ignore
            np.save(out / "embeddings.npy", self.vecs)
        with open(out / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, in_dir: str, embedder: Optional[Embedder] = None) -> "Index":
        p = pathlib.Path(in_dir)
        chunks: List[Dict] = []
        with open(p / "chunks.jsonl", encoding="utf-8") as f:
            for line in f:
                chunks.append(json.loads(line))

        idx = cls.__new__(cls)
        idx.chunks = chunks
        idx.by_id = {c["id"]: c for c in chunks}
        idx.called_by = defaultdict(list)
        for c in chunks:
            for ref in c["meta"]["refs"]:
                fn = ref.rsplit(".", 1)[-1]
                idx.called_by[fn].append(c["id"])

        with open(p / "bm25.pkl", "rb") as f:
            d = pickle.load(f)
        idx.tokens = d["tokens"]
        idx.bm25 = BM25(idx.tokens, k1=d.get("k1", 1.5), b=d.get("b", 0.75))

        manifest = {}
        mp = p / "manifest.json"
        if mp.exists():
            manifest = json.loads(mp.read_text(encoding="utf-8"))
        idx.model_name = manifest.get("model")
        idx.embedder = embedder
        idx.vecs = None
        emb_path = p / "embeddings.npy"
        if emb_path.exists() and embedder and embedder.ok:
            try:
                import numpy as np  # type: ignore
                idx.vecs = np.load(emb_path)
            except Exception as e:
                print(f"  warning: failed to load dense embeddings ({e})", file=sys.stderr)
        return idx


def _rrf(rank_lists: List[List[int]], k_const: int = 60) -> List[int]:
    """Reciprocal Rank Fusion of multiple ranked-id lists."""
    scores: Dict[int, float] = defaultdict(float)
    for lst in rank_lists:
        for r, i in enumerate(lst):
            scores[i] += 1.0 / (k_const + r + 1)
    return sorted(scores, key=lambda i: -scores[i])


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------
def _print_hit(i: int, c: Dict, show_body: bool = False) -> None:
    m = c["meta"]
    print(f"\n[{i + 1}] {m['kind']:<7} {m['source']}:{m['lineno']}")
    if m.get("class"):
        print(f"    class: {m['class']}")
    print(f"    func : {m['function']}{m['signature']}")
    if m["tags"]:
        print(f"    ops  : {','.join(m['tags'])}")
    if m["markers"]:
        print(f"    marks: {','.join(m['markers'])}")
    if m["docstring"]:
        first = m["docstring"].strip().split("\n")[0]
        print(f"    doc  : {first[:100]}")
    if show_body:
        print("    ---")
        for line in c["text"].split("\n")[:30]:
            print(f"    {line}")


# ---------------------------------------------------------------------------
# CLI handlers
# ---------------------------------------------------------------------------
def cmd_build(args) -> None:
    root = pathlib.Path(args.dir).resolve()
    if not root.is_dir():
        sys.exit(f"error: not a directory: {root}")
    print(f"scanning {root} ...", file=sys.stderr)
    chunks = scan_repo(root)
    if not chunks:
        sys.exit("error: no chunks extracted (empty / all syntax-error / wrong dir?)")

    embedder: Optional[Embedder] = None
    if not args.no_dense:
        embedder = Embedder(args.model)
        if not embedder.ok:
            print(
                f"  warning: dense embeddings unavailable "
                f"({embedder.err}); BM25-only.\n"
                f"  install with:  pip install sentence-transformers",
                file=sys.stderr,
            )
            embedder = None

    idx = Index(chunks, embedder=embedder, model_name=args.model if embedder else None)
    idx.save(args.out)

    n_test = sum(1 for c in chunks if c["meta"]["kind"] == "test")
    n_helper = sum(1 for c in chunks if c["meta"]["kind"] == "helper")
    n_fix = sum(1 for c in chunks if c["meta"]["kind"] == "fixture")
    tag_counts: Counter = Counter()
    for c in chunks:
        for t in c["meta"]["tags"]:
            tag_counts[t] += 1
    print(f"\nbuild complete: {len(chunks)} chunks -> {args.out}")
    print(f"  tests   : {n_test}")
    print(f"  helpers : {n_helper}")
    print(f"  fixtures: {n_fix}")
    if tag_counts:
        print(f"  ops tags: {dict(tag_counts.most_common())}")
    print(f"  dense   : {'yes (' + str(idx.vecs.shape[1]) + 'd)' if idx.vecs is not None else 'no'}")


def cmd_query(args) -> None:
    embedder: Optional[Embedder] = None
    if not args.no_dense:
        embedder = Embedder(args.model)
        if not embedder.ok:
            embedder = None
    idx = Index.load(args.kb, embedder=embedder)

    filters: Dict = {}
    if args.kind:
        filters["kind"] = args.kind
    if args.tag:
        filters["tags"] = [args.tag]

    hits = idx.search(args.text, k=args.k, filters=filters)
    if not hits:
        print("(no hits)")
        return
    for i, h in enumerate(hits):
        _print_hit(i, h, show_body=args.show_body)


def cmd_helpers(args) -> None:
    idx = Index.load(args.kb, embedder=None)
    by_tag: Dict[str, List[Dict]] = defaultdict(list)
    for c in idx.chunks:
        if c["meta"]["kind"] not in ("helper", "fixture"):
            continue
        if args.tag and args.tag not in c["meta"]["tags"]:
            continue
        if c["meta"]["tags"]:
            for t in c["meta"]["tags"]:
                by_tag[t].append(c)
        else:
            by_tag["(untagged)"].append(c)

    if not by_tag:
        print("(no helpers matched)")
        return

    for tag in sorted(by_tag.keys()):
        cs = by_tag[tag]
        cs.sort(key=lambda c: -len(idx.called_by.get(c["meta"]["function"], [])))
        print(f"\n[{tag}]  {len(cs)} entries")
        for c in cs[: args.limit]:
            m = c["meta"]
            uses = len(idx.called_by.get(m["function"], []))
            class_pfx = f"{m['class']}." if m["class"] else ""
            print(f"  {class_pfx}{m['function']:<32}  {m['source']}:{m['lineno']}  (used {uses}x)")
        if len(cs) > args.limit:
            print(f"  ... ({len(cs) - args.limit} more)")


def cmd_users(args) -> None:
    idx = Index.load(args.kb, embedder=None)
    callers = idx.called_by.get(args.name, [])
    if not callers:
        print(f"(nothing in the kb calls '{args.name}')")
        return
    print(f"{len(callers)} chunks call '{args.name}':\n")
    rows: List[Tuple[str, Dict]] = []
    for cid in callers:
        c = idx.by_id.get(cid)
        if c:
            rows.append((c["meta"]["source"], c))
    rows.sort(key=lambda r: r[0])
    for _, c in rows:
        m = c["meta"]
        class_pfx = f"{m['class']}." if m["class"] else ""
        print(f"  {m['source']}:{m['lineno']}  {class_pfx}{m['function']} ({m['kind']})")


def cmd_ask(args) -> None:
    url = os.environ.get("LLM_URL")
    if not url:
        sys.exit(
            "error: set LLM_URL to your internal OpenAI-compatible /chat/completions endpoint.\n"
            "  optional: LLM_MODEL (default: 'default'), LLM_API_KEY"
        )
    model = os.environ.get("LLM_MODEL", "default")
    api_key = os.environ.get("LLM_API_KEY")

    embedder: Optional[Embedder] = None
    if not args.no_dense:
        embedder = Embedder(args.model)
        if not embedder.ok:
            embedder = None
    idx = Index.load(args.kb, embedder=embedder)

    hits = idx.search(args.question, k=args.k)

    # Attach a couple usage examples for each helper hit.
    blocks: List[str] = []
    sources: List[str] = []
    for h in hits:
        m = h["meta"]
        sources.append(f"{m['source']}:{m['lineno']}  {m['function']} ({m['kind']})")
        block = h["text"]
        if m["kind"] in ("helper", "fixture"):
            usages = idx.called_by.get(m["function"], [])[:2]
            for u_id in usages:
                u = idx.by_id.get(u_id)
                if not u:
                    continue
                um = u["meta"]
                snippet = "\n".join(u["text"].split("\n")[:20])
                block += (
                    f"\n\n  # usage example ({um['source']}:{um['lineno']} "
                    f"{um['function']}):\n  " + snippet.replace("\n", "\n  ")
                )
        blocks.append(block)

    context = "\n\n---\n\n".join(blocks) if blocks else "(no relevant chunks found)"

    sys_msg = (
        "你是公司内部测试库智能助手。仅根据用户给你的【项目内代码片段】回答问题或合成新脚本。"
        "不要编造未在片段中出现的 API、fixture 或导入。"
        "若用户在让你写脚本,严格仿照例子的导入、风格和 helper 名;"
        "若片段不足以回答,如实说出来。"
    )
    user_msg = (
        f"【知识片段】\n{context}\n\n"
        f"【用户问题 / 任务】\n{args.question}\n\n"
        "（请在回答末尾用一行列出你用到了哪些 source 文件）"
    )

    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": user_msg},
            ],
            "temperature": 0.2,
            "max_tokens": args.max_tokens,
        },
        ensure_ascii=False,
    ).encode("utf-8")

    import urllib.request
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        sys.exit(f"error: LLM call failed: {e}")

    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        sys.exit(f"error: unexpected LLM response shape: {payload}")

    print(content)
    print("\n— retrieved sources —")
    for s in sources:
        print(f"  {s}")


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> None:
    p = argparse.ArgumentParser(
        prog="testkb",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build", help="index a Python testcase directory")
    pb.add_argument("dir", help="repo root to scan (recurses; skips .venv/__pycache__/etc.)")
    pb.add_argument("--out", default="./testkb_index", help="output dir (default: ./testkb_index)")
    pb.add_argument("--model", default="BAAI/bge-m3", help="dense embedding model")
    pb.add_argument("--no-dense", action="store_true", help="skip dense embeddings (BM25-only)")
    pb.set_defaults(fn=cmd_build)

    pq = sub.add_parser("query", help="search the kb (returns top hits)")
    pq.add_argument("text")
    pq.add_argument("--kb", default="./testkb_index")
    pq.add_argument("--k", type=int, default=8)
    pq.add_argument("--kind", choices=["helper", "fixture", "test"])
    pq.add_argument("--tag", help="filter to an operation tag (start/stop/init/cleanup/wait/verify/config/mock)")
    pq.add_argument("--show-body", action="store_true", help="also print top of each chunk's body")
    pq.add_argument("--model", default="BAAI/bge-m3")
    pq.add_argument("--no-dense", action="store_true")
    pq.set_defaults(fn=cmd_query)

    ph = sub.add_parser("helpers", help="browse helpers/fixtures grouped by operation tag")
    ph.add_argument("--kb", default="./testkb_index")
    ph.add_argument("--tag", help="restrict to a single op tag")
    ph.add_argument("--limit", type=int, default=15, help="max entries per tag (default: 15)")
    ph.set_defaults(fn=cmd_helpers)

    pu = sub.add_parser("users", help="reverse: which chunks call this function name")
    pu.add_argument("name", help="function / fixture name (bare, e.g. 'start_service')")
    pu.add_argument("--kb", default="./testkb_index")
    pu.set_defaults(fn=cmd_users)

    pa = sub.add_parser(
        "ask",
        help="full RAG: retrieve relevant code + ask LLM to answer/synthesize",
    )
    pa.add_argument("question")
    pa.add_argument("--kb", default="./testkb_index")
    pa.add_argument("--k", type=int, default=6)
    pa.add_argument("--max-tokens", type=int, default=2048)
    pa.add_argument("--model", default="BAAI/bge-m3", help="embedding model (not the LLM)")
    pa.add_argument("--no-dense", action="store_true")
    pa.set_defaults(fn=cmd_ask)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
