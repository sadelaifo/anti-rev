#!/usr/bin/env python3
"""
pyarmor_compat_scan  -  statically flag scripts that PyArmor may break.

PyArmor obfuscates by transforming/encrypting bytecode and installing a
runtime import hook.  Anything that reads a function's *real* bytecode or
source, ships a *function* to another process, or (in rename mode) resolves
names dynamically can break.  This tool parses every ``.py`` under a tree with
the ``ast`` module and reports the at-risk patterns, ranked by severity, so you
know which modules to EXCLUDE from obfuscation (or feed to
``encryptor/pyarmor_verify.py`` for a behavioural check).

It is a PRE-FILTER, not a proof of safety:
  * it catches syntactic patterns (import X, @decorator, call foo())
  * it CANNOT catch dynamic cases (getattr(m, name_from_config)(), a function
    pickled only under a runtime branch, spawn chosen via env var).
Treat the output as a triage list; confirm behaviour with pyarmor_verify.py.

Severity:
  HIGH    almost certainly breaks under obfuscation -> exclude the module
  MEDIUM  breaks in common configs (spawn, dynamic exec) -> review
  LOW     only matters in specific modes (RFT rename / BCC) -> mode-dependent
  INFO    worth knowing, usually fine

Usage:
  tools/pyarmor_compat_scan.py /path/to/pysuite
  tools/pyarmor_compat_scan.py . --json > report.json
  tools/pyarmor_compat_scan.py src --min-severity MEDIUM
  tools/pyarmor_compat_scan.py src --no-rft --no-bcc      # basic mode only
  tools/pyarmor_compat_scan.py src --exclude tests --exclude build

Exit code is non-zero when a finding at or above --fail-on (default HIGH) is
present, so it can gate CI.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

# --- dotted callables that are hard breakers, keyed to a category ---
# JIT / bytecode-compiling decorators: PyArmor-transformed bytecode is
# unreadable to these compilers (see the Numba "analyzing bytecode" failure).
JIT_CALLABLES = {
    "numba.jit", "numba.njit", "numba.vectorize", "numba.guvectorize",
    "numba.stencil", "numba.cfunc", "numba.cuda.jit", "numba.experimental.jitclass",
}
# Reading source / bytecode of live objects -> nothing there after obfuscation.
SOURCE_CALLABLES = {
    "inspect.getsource", "inspect.getsourcelines", "inspect.getsourcefile",
    "inspect.getcomments", "dis.dis", "dis.Bytecode", "dis.get_instructions",
}
# marshal round-trips code objects; blocked / meaningless once obfuscated.
MARSHAL_CALLABLES = {"marshal.dumps", "marshal.loads"}
# Anti-debug commonly disables tracing -> profilers/coverage/debuggers die.
TRACE_CALLABLES = {"sys.settrace", "sys.setprofile", "threading.settrace", "threading.setprofile"}
# Ships a FUNCTION across a process boundary -> can't marshal obfuscated code.
FUNC_SERIALIZE_CALLABLES = {
    "multiprocessing.set_start_method", "multiprocessing.get_context",
    "concurrent.futures.ProcessPoolExecutor",
}
# Dynamic code paths  -  usually fine, but interact with import hooks / BCC.
DYNAMIC_EXEC_NAMES = {"exec", "eval", "compile"}
RFT_ATTR_BUILTINS = {"getattr", "setattr", "hasattr", "delattr"}

# --- #4 resource-path / loader assumptions ---
# Obfuscation changes __file__/__loader__; packaged-data reads via the loader
# can fail, and paths computed from __file__ may point at the obfuscated file.
RESOURCE_CALLABLES = {
    "pkg_resources.resource_filename", "pkg_resources.resource_string",
    "pkg_resources.resource_stream", "pkg_resources.resource_listdir",
    "importlib.resources.files", "importlib.resources.path",
    "importlib.resources.read_text", "importlib.resources.read_binary",
    "importlib.resources.open_text", "importlib.resources.open_binary",
    "pkgutil.get_data",
}
# path builders that are a problem only when fed __file__
PATH_FROM_FILE_CALLABLES = {
    "os.path.dirname", "os.path.abspath", "os.path.realpath", "os.path.join",
    "pathlib.Path",
}
FRAME_INTROSPECT_CALLABLES = {
    "inspect.stack", "inspect.currentframe", "inspect.getframeinfo",
    "inspect.trace",
}
# --- #6 dynamic name resolution (RFT rename mode) ---
RFT_NAME_CALLABLES = {"operator.attrgetter", "operator.methodcaller"}

# module imports that are, on their own, a signal
IMPORT_SIGNALS = {
    # module -> (severity, category, note)
    "numba": ("HIGH", "numba-jit", "Numba JIT  -  obfuscated bytecode is unreadable to it; exclude jitted funcs"),
    "coverage": ("HIGH", "profiler", "coverage.py uses settrace; PyArmor anti-debug blocks it"),
    "line_profiler": ("HIGH", "profiler", "line_profiler uses settrace; blocked by anti-debug"),
    "memory_profiler": ("MEDIUM", "profiler", "memory_profiler traces; may be blocked"),
    "dill": ("HIGH", "func-serialization", "dill pickles functions/code  -  fails on obfuscated code objects"),
    "cloudpickle": ("HIGH", "func-serialization", "cloudpickle exists to serialize functions  -  fails on obfuscated code"),
    "celery": ("HIGH", "func-serialization", "Celery ships task functions to workers  -  obfuscated code won't marshal"),
    "joblib": ("MEDIUM", "func-serialization", "joblib.Parallel may pickle functions to worker processes"),
    "Cython": ("INFO", "compiled", "Cython output is already compiled  -  can't/needn't be obfuscated"),
    "cython": ("INFO", "compiled", "Cython output is already compiled  -  can't/needn't be obfuscated"),
    "sqlalchemy": ("LOW", "rft", "ORM maps columns to attribute names  -  RFT rename can break mapping"),
    "django": ("LOW", "rft", "Django ORM/forms map fields to attribute names  -  RFT rename risk"),
    "pytest": ("MEDIUM", "test", "pytest rewrites test bytecode for asserts  -  don't obfuscate tests"),
    "sphinx": ("MEDIUM", "source-introspection", "Sphinx autodoc reads source/docstrings  -  gone after obfuscation"),
}


def dotted_name(node):
    """Return the dotted attribute chain for a Name/Attribute node, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class Scanner(ast.NodeVisitor):
    def __init__(self, path, opts):
        self.path = path
        self.opts = opts
        self.aliases = {}          # local name -> full dotted module/callable path
        self.findings = []         # (line, severity, category, message)
        self._imported_mods = set()

    # ---- finding helper -------------------------------------------------
    def add(self, line, severity, category, message):
        if category == "rft" and self.opts.no_rft:
            return
        if category == "bcc" and self.opts.no_bcc:
            return
        self.findings.append((line, severity, category, message))

    # ---- resolve a call/decorator node to its full dotted path ----------
    def resolve(self, node):
        if isinstance(node, ast.Call):
            node = node.func
        dn = dotted_name(node)
        if dn is None:
            return None
        head, _, rest = dn.partition(".")
        if head in self.aliases:
            base = self.aliases[head]
            return base if not rest else f"{base}.{rest}"
        return dn

    # ---- imports: build the alias map ----------------------------------
    def visit_Import(self, node):
        for a in node.names:
            local = a.asname or a.name.split(".")[0]
            full = a.name if a.asname else a.name.split(".")[0]
            self.aliases[local] = a.name if a.asname else full
            top = a.name.split(".")[0]
            self._imported_mods.add(top)
            self._flag_import(top, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        top = mod.split(".")[0]
        if mod:
            self._imported_mods.add(top)
            self._flag_import(top, node.lineno)
        for a in node.names:
            local = a.asname or a.name
            self.aliases[local] = f"{mod}.{a.name}" if mod else a.name
        # antirev_client's own import hook can race PyArmor's import hook
        if top == "antirev_client" or mod == "antirev_client":
            self.add(node.lineno, "MEDIUM", "import-hook",
                     "imports antirev_client  -  its sys.meta_path/ctypes patch may "
                     "interact with PyArmor's runtime import hook; test this path")
        self.generic_visit(node)

    def _flag_import(self, top, line):
        if top in IMPORT_SIGNALS:
            sev, cat, note = IMPORT_SIGNALS[top]
            self.add(line, sev, cat, f"imports '{top}': {note}")

    # ---- decorators (the actionable "exclude this function" signal) -----
    def _check_decorators(self, node):
        for dec in node.decorator_list:
            full = self.resolve(dec)
            if full in JIT_CALLABLES:
                self.add(dec.lineno, "HIGH", "numba-jit",
                         f"@{full.split('.')[-1]} on '{node.name}()'  -  JIT compiler "
                         f"reads real bytecode; EXCLUDE this function from obfuscation")
            elif full in ("celery.shared_task",) or (full and full.endswith(".task")):
                self.add(dec.lineno, "HIGH", "func-serialization",
                         f"task decorator on '{node.name}()'  -  worker must marshal the "
                         f"function; obfuscated code won't pickle")

    def visit_FunctionDef(self, node):
        self._check_decorators(node)
        self._check_bcc(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_decorators(node)
        self.add(node.lineno, "LOW", "bcc",
                 f"'async def {node.name}'  -  some PyArmor BCC/bytecode-to-C versions "
                 f"don't support async; review if using BCC mode")
        self.generic_visit(node)

    def _check_bcc(self, node):
        # BCC (bytecode-to-C) mode has feature gaps; flag constructs to review.
        for n in ast.walk(node):
            if isinstance(n, (ast.Yield, ast.YieldFrom)):
                self.add(n.lineno, "LOW", "bcc",
                         f"generator (yield) in '{node.name}'  -  verify under BCC mode")
                break
        for n in ast.walk(node):
            if isinstance(n, ast.Nonlocal):
                self.add(n.lineno, "LOW", "bcc",
                         f"nonlocal/closure in '{node.name}'  -  verify under BCC mode")
                break

    # ---- calls ----------------------------------------------------------
    def visit_Call(self, node):
        full = self.resolve(node)
        if full in JIT_CALLABLES:
            self.add(node.lineno, "HIGH", "numba-jit",
                     f"{full}() call  -  JIT reads real bytecode; exclude the target")
        elif full in SOURCE_CALLABLES:
            self.add(node.lineno, "HIGH", "source-introspection",
                     f"{full}()  -  reads source/bytecode that obfuscation removes")
        elif full in MARSHAL_CALLABLES:
            self.add(node.lineno, "MEDIUM", "bytecode-introspection",
                     f"{full}()  -  marshals code objects; meaningless/blocked once obfuscated")
        elif full in TRACE_CALLABLES:
            self.add(node.lineno, "HIGH", "trace-hooks",
                     f"{full}()  -  PyArmor anti-debug commonly disables tracing")
        elif full in FUNC_SERIALIZE_CALLABLES:
            self._check_spawn(node, full)
        elif full == "inspect.signature" or full == "inspect.getfullargspec":
            self.add(node.lineno, "LOW", "source-introspection",
                     f"{full}()  -  usually OK, but breaks if RFT renames params/args")
        elif full in ("importlib.reload",):
            self.add(node.lineno, "LOW", "import-hook",
                     "importlib.reload() on an obfuscated module can misbehave")
        elif full in RESOURCE_CALLABLES:
            self.add(node.lineno, "MEDIUM", "resource-path",
                     f"{full}()  -  reads packaged data via the loader; obfuscation "
                     f"changes __loader__/__file__ and this can fail")
        elif full in FRAME_INTROSPECT_CALLABLES:
            self.add(node.lineno, "LOW", "source-introspection",
                     f"{full}()  -  frame/source introspection; line/source info is "
                     f"degraded after obfuscation")
        elif full in RFT_NAME_CALLABLES:
            self.add(node.lineno, "LOW", "rft",
                     f"{full}()  -  resolves attributes by name; RFT rename mode may break it")
        elif full in PATH_FROM_FILE_CALLABLES and self._refs_dunder_file(node):
            self.add(node.lineno, "LOW", "resource-path",
                     f"{full}(__file__ ...)  -  path derived from __file__; obfuscation "
                     f"may move __file__, so sibling data files may not resolve")

        # builtins (not import-resolved)
        fn = node.func
        if isinstance(fn, ast.Name):
            if fn.id in DYNAMIC_EXEC_NAMES:
                self.add(node.lineno, "MEDIUM", "dynamic-exec",
                         f"{fn.id}()  -  dynamic code; interacts with PyArmor import hook / BCC")
            elif fn.id in RFT_ATTR_BUILTINS and len(node.args) >= 2:
                name_arg = node.args[1]
                is_literal = isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)
                if not is_literal:
                    self.add(node.lineno, "LOW", "rft",
                             f"{fn.id}() with a computed name  -  RFT rename mode may break "
                             f"dynamic attribute access")
            elif fn.id in ("globals", "vars", "locals"):
                self.add(node.lineno, "LOW", "rft",
                         f"{fn.id}()  -  name-keyed access; RFT rename mode may break lookups")
            elif fn.id == "open" and self._refs_dunder_file(node):
                self.add(node.lineno, "MEDIUM", "resource-path",
                         "open() on a path derived from __file__  -  obfuscation may change "
                         "__file__; verify data files still resolve (and it won't read plaintext "
                         "source of itself)")
            elif fn.id == "type" and len(node.args) == 3:
                self.add(node.lineno, "LOW", "rft",
                         "type(name, bases, dict)  -  dynamic class creation is name-based; "
                         "RFT rename mode may affect name-keyed registries")
        elif isinstance(fn, ast.Attribute) and fn.attr == "get_data":
            self.add(node.lineno, "LOW", "resource-path",
                     ".get_data()  -  loader data access (e.g. __loader__.get_data); "
                     "obfuscation changes the loader")
        self.generic_visit(node)

    def _check_spawn(self, node, full):
        if full == "concurrent.futures.ProcessPoolExecutor":
            self.add(node.lineno, "MEDIUM", "func-serialization",
                     "ProcessPoolExecutor  -  pickles the submitted callable to a child; "
                     "obfuscated functions won't marshal (esp. under 'spawn')")
            return
        # multiprocessing.set_start_method('spawn') / get_context('spawn')
        for a in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(a, ast.Constant) and a.value == "spawn":
                self.add(node.lineno, "MEDIUM", "func-serialization",
                         "multiprocessing 'spawn' start method re-imports & pickles the "
                         "target; obfuscated code can fail to load in the child")
                return

    @staticmethod
    def _refs_dunder_file(node):
        return any(isinstance(n, ast.Name) and n.id == "__file__"
                   for n in ast.walk(node))

    # ---- class-name-keyed registries (RFT) ------------------------------
    def visit_Attribute(self, node):
        if node.attr in ("__name__", "__qualname__"):
            self.add(node.lineno, "LOW", "rft",
                     f"uses .{node.attr}  -  if used as a registry key / dispatch, RFT "
                     f"rename mode changes it")
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        for kw in node.keywords:
            if kw.arg == "metaclass":
                self.add(node.lineno, "LOW", "rft",
                         f"class '{node.name}' uses a metaclass  -  metaclass registries "
                         f"often key on class names; RFT rename mode may break them")
                break
        self.generic_visit(node)


def scan_file(path, opts):
    try:
        src = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [(0, "HIGH", "unreadable", f"cannot read file: {e}")]
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [(e.lineno or 0, "HIGH", "syntax-error",
                 f"does not parse ({e.msg})  -  PyArmor can't obfuscate it either")]
    sc = Scanner(path, opts)
    sc.visit(tree)
    # de-dup identical (line, category, message)
    seen = set()
    uniq = []
    for f in sc.findings:
        key = (f[0], f[2], f[3])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def iter_py_files(root, excludes):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in excludes and not d.startswith(".")
                       and d != "__pycache__"]
        for fn in filenames:
            if fn.endswith(".py"):
                p = Path(dirpath) / fn
                if not any(ex in p.parts for ex in excludes):
                    yield p


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Statically flag scripts PyArmor may break.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("root", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", default="INFO",
                    choices=list(SEVERITY_ORDER), help="hide findings below this level")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=list(SEVERITY_ORDER),
                    help="exit non-zero if any finding at/above this level (default HIGH)")
    ap.add_argument("--no-rft", action="store_true",
                    help="skip RFT/rename-mode checks (use if not using rename mode)")
    ap.add_argument("--no-bcc", action="store_true",
                    help="skip BCC/bytecode-to-C checks (use if not using BCC mode)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="directory name/part to skip (repeatable)")
    opts = ap.parse_args(argv)

    min_sev = SEVERITY_ORDER[opts.min_severity]
    results = {}   # path -> [findings]
    for path in iter_py_files(opts.root, set(opts.exclude)):
        findings = [f for f in scan_file(path, opts) if SEVERITY_ORDER[f[1]] >= min_sev]
        if findings:
            findings.sort(key=lambda f: (-SEVERITY_ORDER[f[1]], f[0]))
            results[str(path)] = findings

    # summary aggregates
    by_cat = {}
    by_sev = {k: 0 for k in SEVERITY_ORDER}
    exclude_candidates = set()
    for path, findings in results.items():
        for line, sev, cat, msg in findings:
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_sev[sev] += 1
            if sev == "HIGH" and cat in ("numba-jit", "func-serialization",
                                         "source-introspection", "trace-hooks"):
                exclude_candidates.add(path)

    worst = max((SEVERITY_ORDER[s] for f in results.values() for (_, s, _, _) in f),
                default=-1)
    exit_code = 1 if worst >= SEVERITY_ORDER[opts.fail_on] else 0

    if opts.json:
        out = {
            "files": {p: [{"line": l, "severity": s, "category": c, "message": m}
                          for (l, s, c, m) in fs] for p, fs in results.items()},
            "summary": {"by_severity": by_sev, "by_category": by_cat,
                        "exclude_candidates": sorted(exclude_candidates),
                        "files_scanned": sum(1 for _ in iter_py_files(opts.root, set(opts.exclude)))},
        }
        print(json.dumps(out, indent=2))
        return exit_code

    if not results:
        print("No PyArmor-compatibility issues found.")
        return exit_code

    for path in sorted(results):
        print(f"\n{path}")
        for line, sev, cat, msg in results[path]:
            print(f"  {sev:6} [{cat}] line {line}: {msg}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print(f"  findings by severity: " +
          ", ".join(f"{k}={by_sev[k]}" for k in ["HIGH", "MEDIUM", "LOW", "INFO"]))
    print(f"  findings by category: " +
          ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items())))
    if exclude_candidates:
        print("\n  >> Modules to EXCLUDE from obfuscation (HIGH breakers):")
        for p in sorted(exclude_candidates):
            print(f"       {p}")
    print("\n  Static pre-filter only  -  confirm with encryptor/pyarmor_verify.py.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
