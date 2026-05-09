#!/usr/bin/env python3
"""expr_compiler — compile a math-expression string into an optimised callable.

Use case: long polynomial / engineering formulas (hundreds of terms,
named variables, scalar inputs) that need to be evaluated millions of
times.  Pure ``eval()`` is ~100us/call; this module gets to ~10-50ns/call.

Pipeline (top → bottom, fast → faster):

    expr string
        │
        │  sympy.sympify
        ▼
    sympy expression tree
        │
        │  sympy.cse — extract common subexpressions
        ▼
    list of (tmp = ...) + final expr
        │
        │  generate Python source, exec
        ▼
    real Python function (LOAD_FAST locals, ~500ns/call)
        │
        │  numba.njit(fastmath=True, cache=True)
        ▼
    JIT-compiled machine code (~10-50ns/call)

CSE is a meaningful win for expressions where the same subterm
(e.g. ``x*y``, ``x**2``) appears in many places.  numba is a meaningful
win for high-frequency calls; if you're calling once per batch on
numpy arrays, prefer ``numexpr.evaluate`` instead — different
optimisation regime.

──────────────────────────────────────────────────────────────────────
                            API reference
──────────────────────────────────────────────────────────────────────

There are five public entry points, picked by how the formula reaches
you:

    in-memory string ──────────────► make_expr_func
                                     make_expr_func_cached  (LRU)

    one formula in a JSON file ────► make_expr_func_from_json

    several formulas in a flat
    or detailed JSON file ─────────► make_funcs_from_json

    formulas scattered through
    a heterogeneous JSON tree ─────► load_expressions_from_json
                                     compile_expressions_in_data


1. make_expr_func(expr_str, params, *, jit=True, fastmath=True,
                  cache=True, debug=False)
   ----------------------------------------------------------------
   The core compiler.  Pass an expression and the positional
   parameter list:

       from expr_compiler import make_expr_func

       f = make_expr_func("a*b + c**2", ["a", "b", "c"])
       f(1.0, 2.0, 3.0)             # → 11.0

   ``params=[]`` is allowed for a fully constant expression.
   ``debug=True`` prints the generated Python source — useful when
   inspecting CSE output or precision of constants.

   Operators understood (anything Python's ``eval`` accepts on the
   same string): ``+ - * / ** ()``, unary minus, scientific notation
   (``1.5e-3``, ``-.5e12``), identifiers with digits / underscores
   (``var1``, ``x_long_name``).  ``**`` is right-associative
   (``2**3**2 == 512``) and binds tighter than ``*``.


2. make_expr_func_cached(expr_str, params_tuple, *, jit, fastmath, cache)
   ----------------------------------------------------------------
   ``functools.lru_cache``-wrapped variant — re-compiling the same
   ``(expr_str, params)`` pair returns the cached function instead
   of paying sympify+cse+exec+numba again.  Note ``params`` must be a
   *tuple* (hashable):

       f = make_expr_func_cached("a*b", ("a", "b"))


3. make_expr_func_from_json(json_path, expr_at, *,
                            constants_at=None, subexprs_at=None,
                            params_at=None, **compile_opts)
   ----------------------------------------------------------------
   Read one formula from a JSON config and compile it.  All path
   arguments accept either a tuple of segments
   (``("device", "transfer", "formula")``) or a dotted-with-bracket
   string (``"device.transfer.formula"``, ``"schedule[0].value"``).

   - ``expr_at`` (required): path to the formula string.
   - ``constants_at``: path to a ``{name: number}`` dict.  Each entry
     is *baked in* as a numeric literal at compile time, so it never
     appears as a function argument.  JSON floats are loaded with
     ``parse_float=str`` and forwarded to ``sp.Float`` as strings,
     so a 12-digit value like ``0.833333333333`` survives verbatim
     into the generated source (no rounding to default 15-dps).
   - ``subexprs_at``: path to a ``{name: expr_string}`` dict.  Each
     named sub-expression is inlined into the main formula via sympy
     AST substitution; entries may reference each other or any
     constant; cycles raise ``ValueError``.  Naming is purely an
     input-side readability feature — sympy's CSE rediscovers any
     common subterm so there's no runtime cost.
   - ``params_at``: optional override for parameter order.  Pass a
     single path or a list of paths, each pointing to a list of
     strings; values are concatenated into the positional-argument
     order.  Default (``None``) auto-detects the surviving free
     symbols and sorts them alphabetically.

   JSON shape this function expects::

       {
         "constants": {"k1": 6.5e-5, "k2": 0.001, "scale": 0.5},
         "subexprs":  {"power": "v*i", "loss":  "k1*v**2 + k2*i**2"},
         "formula":   "scale*power - loss"
       }

   Compile and call::

       from expr_compiler import make_expr_func_from_json

       f = make_expr_func_from_json(
           "config.json",
           expr_at      = "formula",
           constants_at = "constants",
           subexprs_at  = "subexprs",
       )
       f(1.5, 220.0)                # auto-detected order: i, v


4. make_funcs_from_json(json_path, **compile_opts) -> {name: callable}
   ----------------------------------------------------------------
   Top-level JSON object whose keys *are* the formula names.  Two
   per-entry shapes are supported and may be mixed::

       {
         "torque":  "0.5 * m * r**2 * omega",            # flat
         "voltage": {                                     # detailed
            "expr":   "I * R + L * dI_dt",
            "params": ["I", "R", "L", "dI_dt"]
         }
       }

   Use the detailed form when you need a non-alphabetical positional
   order, or when a variable name collides with a sympy constant
   (``E``, ``I``, ``pi``) and auto-detection would miss it.


5. load_expressions_from_json(json_path, is_expr, **compile_opts)
   compile_expressions_in_data(data, is_expr, **compile_opts)
   ----------------------------------------------------------------
   For files where formulas are *embedded* in an otherwise
   heterogeneous tree.  The walker recurses through dicts and lists,
   asks ``is_expr(path, value)`` at every leaf, and replaces only the
   matched ones with compiled callables — everything else passes
   through unchanged.

   Common predicate shapes::

       # Any string under a key named "formula" / "expr":
       lambda p, v: isinstance(v, str) and p and p[-1] in ("formula", "expr")

       # Specific path only:
       lambda p, v: p == ("device", "transfer_func")

       # Sentinel-prefix convention:
       lambda p, v: isinstance(v, str) and v.startswith("=")


Helper utilities
----------------

- ``get_at_path(data, path)`` — same path syntax as the loaders;
  raises ``KeyError`` / ``IndexError`` / ``TypeError`` with the
  failing segment named.  Useful for pulling unrelated fields out of
  the same JSON file.

This module is unrelated to antirev's runtime; it lives under tools/
because that's where the project keeps general-purpose helpers.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

import sympy as sp


def make_expr_func(expr_str: str, params: list[str], *,
                   jit: bool = True, fastmath: bool = True,
                   cache: bool = True, debug: bool = False):
    """Compile ``expr_str`` into a callable f(p1, p2, ...).

    Parameters
    ----------
    expr_str  : Python math expression, e.g. ``"-.5e-12*x**7*y**2*z + .18188888*x"``.
    params    : variable names occurring in expr_str, in the order they should
                become positional parameters of the returned function.
    jit       : if True (default), compile to machine code via numba.njit.
                Set False to fall back to a pure-Python exec'd function (no
                numba dependency, ~10x slower than JIT).
    fastmath  : numba fastmath knob.  Lets LLVM reorder ops, use FMA, etc.
                Significant win on long polynomials but assumes no NaN/Inf
                inputs.  Disable if your domain admits NaN.
    cache     : numba caches the compiled binary on disk so subsequent
                process starts skip the JIT compile.
    debug     : print the generated Python source — useful when checking
                what CSE produced.

    Returns
    -------
    callable f(p1, p2, ...) -> float
    """
    # 1. sympify — bind variable names to sympy Symbols so they're not
    #    misread as imports or function names.  Empty params (a fully
    #    constant expression) is allowed; sp.symbols('') would error
    #    so handle that case first.
    if params:
        syms = sp.symbols(' '.join(params))
        if not isinstance(syms, tuple):       # single-param case
            syms = (syms,)
    else:
        syms = ()
    expr = sp.sympify(expr_str, locals=dict(zip(params, syms)))

    # 2. CSE — let sympy find repeated subterms across the whole expression
    #    and replace them with intermediates.  cheap on small/medium expr;
    #    on multi-thousand-term inputs you may want optimizations=[] to
    #    skip the more expensive passes.
    sub_exprs, [main] = sp.cse(expr, optimizations='basic')

    # 3. Generate Python source.  sp.pycode is stricter than str() — it
    #    won't emit Rational(1,2) or other sympy-specific literals that
    #    Python can't parse.
    lines = [f"def _expr({', '.join(params)}):"]
    for tmp, val in sub_exprs:
        lines.append(f"    {tmp} = {sp.pycode(val)}")
    lines.append(f"    return {sp.pycode(main)}")
    src = "\n".join(lines) + "\n"

    if debug:
        print("--- generated source ---")
        print(src)
        print(f"--- {len(sub_exprs)} CSE temps ---")

    ns: dict = {}
    exec(src, ns)
    fn = ns['_expr']

    # 4. numba JIT.  Imported lazily so the pure-Python path doesn't pay
    #    the import cost when jit=False.
    if jit:
        from numba import njit
        fn = njit(cache=cache, fastmath=fastmath)(fn)

    return fn


@functools.lru_cache(maxsize=128)
def make_expr_func_cached(expr_str: str, params: tuple[str, ...], *,
                          jit: bool = True, fastmath: bool = True,
                          cache: bool = True):
    """LRU-cached wrapper.  Re-compiling the same (expr_str, params) pair
    returns the same compiled function instead of paying the
    sympify+cse+exec+numba cost again.

    ``params`` must be a tuple (hashable).
    """
    return make_expr_func(expr_str, list(params),
                          jit=jit, fastmath=fastmath, cache=cache)


# ---------------------------------------------------------------------
# JSON loader — compile a whole file of formulas in one call.
# ---------------------------------------------------------------------
def _detect_params(expr_str: str) -> list[str]:
    """Return alphabetically-sorted free-symbol names in expr_str.

    Sympy's ``sympify`` distinguishes free symbols (variables) from
    known constants like ``pi``, ``E``, ``I`` and from function names
    like ``sin``, ``log``, so we get exactly the names that the
    generated function should accept as arguments.

    If you have a variable that collides with a sympy constant — the
    classic gotchas are ``E`` and ``I`` — pass an explicit ``params``
    list via the detailed JSON form below; auto-detect can't see them
    as free.
    """
    return sorted(str(s) for s in sp.sympify(expr_str).free_symbols)


def get_at_path(data, path):
    """Navigate ``data`` (a nested dict / list structure) along ``path``
    and return the value found there.

    ``path`` accepts two equivalent forms:

      1. Tuple / list of keys and indices, no ambiguity::

             get_at_path(d, ("formulas", "torque", "inputs"))
             get_at_path(d, ("schedule", 0, "value"))

      2. Dotted-with-bracket string for convenience::

             get_at_path(d, "formulas.torque.inputs")
             get_at_path(d, "schedule[0].value")

    Raises ``KeyError`` / ``IndexError`` / ``TypeError`` with a message
    that names the offending segment, so failures point straight at
    the wrong path component instead of leaving the caller to bisect.
    """
    if isinstance(path, str):
        segments = _parse_path_string(path)
    else:
        segments = tuple(path)

    cur = data
    for i, seg in enumerate(segments):
        try:
            cur = cur[seg]
        except (KeyError, IndexError, TypeError) as e:
            crumb = '.'.join(repr(s) for s in segments[:i + 1])
            raise type(e)(f"path lookup failed at segment {i} "
                          f"({crumb!r}): {e}") from None
    return cur


def _parse_path_string(s: str):
    """`"a.b[0].c"` → `("a", "b", 0, "c")`.  Tolerates absence of dot
    before a bracket: `a[0][1].b` works."""
    out: list = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '.':
            i += 1
            continue
        if s[i] == '[':
            j = s.index(']', i)
            tok = s[i + 1:j].strip()
            if not tok or not (tok.lstrip('-').isdigit()):
                raise ValueError(f"non-integer index in path: {s!r}")
            out.append(int(tok))
            i = j + 1
            continue
        # plain key — read up to next '.' or '['
        j = i
        while j < n and s[j] not in '.[':
            j += 1
        if j == i:
            raise ValueError(f"empty segment in path: {s!r}")
        out.append(s[i:j])
        i = j
    return tuple(out)


def _normalize_paths(p):
    """A single path (str or tuple) becomes ``[p]``; a list of paths is
    returned unchanged.  See :func:`get_at_path` for path syntax.

    Note the convention: a *tuple* of strings is one path with multiple
    segments (``("formulas", "torque")``); a *list* of strings is
    several single-segment paths (``["inputs", "constants"]``).
    """
    if isinstance(p, (str, tuple)):
        return [p]
    if isinstance(p, list):
        if not all(isinstance(x, (str, tuple)) for x in p):
            raise TypeError(f"list of paths must contain only str or tuple "
                            f"elements, got {p!r}")
        return p
    raise TypeError(f"path argument must be str / tuple / list, "
                    f"got {type(p).__name__}")


def _expand_subexprs(expr_str: str, subexprs: dict) -> str:
    """Resolve named sub-expressions into ``expr_str`` so the result is
    a single self-contained expression that :func:`make_expr_func` can
    compile.

    ``subexprs`` is a ``{name: expression_str}`` dict; entries may
    reference each other.  Substitution is done at the sympy AST level
    (``xreplace``), not as text, so a name being a substring of another
    identifier is not a hazard.

    Iterate to a fixed point so chains like ``a -> b -> c`` resolve in
    one call.  Cycles raise ``ValueError``.

    Note: this is purely an *input-side* convenience — sympy's CSE
    pass inside :func:`make_expr_func` will rediscover any common
    subexpression in the inlined formula, so you pay no runtime cost
    for naming them in JSON.
    """
    sub_dict = {sp.Symbol(name): sp.sympify(expr) for name, expr in subexprs.items()}

    # Resolve sub_dict against itself — depth bounded by len(sub_dict),
    # so a normal chain converges within that many iterations.
    for _ in range(len(sub_dict) + 1):
        changed = False
        for sym, expr in list(sub_dict.items()):
            new_expr = expr.xreplace(sub_dict)
            if new_expr != expr:
                sub_dict[sym] = new_expr
                changed = True
        if not changed:
            break

    # A cycle converges too — to a pathological state where some entry
    # still resolves to one of the subexpr names (e.g. ``{a: b, b: a}``
    # settles at ``a -> a, b -> a``).  Catch that by checking for any
    # surviving subexpr-name references in the resolved values.
    sub_names = set(sub_dict)
    for sym, expr in sub_dict.items():
        leftover = expr.free_symbols & sub_names
        if leftover:
            raise ValueError(
                f"subexpression cycle: {sym} still depends on "
                f"{sorted(str(s) for s in leftover)} after substitution")

    return str(sp.sympify(expr_str).xreplace(sub_dict))


def _substitute_constants(expr_str: str, constants: dict) -> str:
    """Bake numeric constants into ``expr_str`` so they appear as
    literal values in the compiled code instead of function arguments.

    Substitution is at the sympy AST level, so a constant whose name
    happens to be a substring of another identifier (e.g. constant
    ``k`` inside variable ``key``) is unaffected.

    Precision handling.  String-form values (``"0.833333333333"``) are
    fed directly to ``sp.Float``, which picks an internal precision
    matching the digit count — this is how :func:`make_expr_func_from_json`
    avoids the IEEE-754 round trip when called via the
    ``parse_float=str`` JSON loader.  Native float values are accepted
    too but are bounded by Python's float precision (~15-17 sig figs).
    Ints become ``sp.Integer``.
    """
    sub_dict: dict = {}
    for name, value in constants.items():
        if isinstance(value, bool):  # bool is an int subclass — exclude
            raise TypeError(f"constant {name!r}: bool is not a numeric value")
        if isinstance(value, str):
            sub_dict[sp.Symbol(name)] = sp.Float(value)
        elif isinstance(value, float):
            sub_dict[sp.Symbol(name)] = sp.Float(value)
        elif isinstance(value, int):
            sub_dict[sp.Symbol(name)] = sp.Integer(value)
        else:
            raise TypeError(f"constant {name!r} must be int / float / "
                            f"numeric-string, got {type(value).__name__}")
    return str(sp.sympify(expr_str).xreplace(sub_dict))


def make_expr_func_from_json(json_path, expr_at, *,
                             constants_at=None, subexprs_at=None,
                             params_at=None, **compile_opts):
    """One-shot: read an expression at ``expr_at``, optionally inline
    named sub-expressions and bake in numeric constants, then return
    the compiled callable.

    Path arguments accept the same forms as :func:`get_at_path` —
    tuples or dotted-with-bracket strings.

    Constants
    ---------
    ``constants_at`` points to a ``{name: number}`` dict.  Each entry
    is substituted into the expression as a numeric literal at compile
    time, so it never appears as a function argument::

        "constants": {"k1": 6.5e-5, "k2": 0.001}

    Sub-expressions
    ---------------
    ``subexprs_at`` points to a ``{name: expr_string}`` dict.  Each
    named expression is inlined into the main formula before
    compilation.  Entries may reference each other and may reference
    constants defined in ``constants_at``; resolution is iterative,
    cycles are caught.

    Parameters (variables)
    ----------------------
    By default, the function's parameters are whatever free symbols
    remain after constant + sub-expression substitution, sorted
    alphabetically — convenient when variable names aren't pinned in
    the JSON ahead of time.

    Pass ``params_at`` (path / list of paths to lists of strings) to
    pin a non-alphabetical positional order.  When given, the listed
    names must be a superset of the surviving free symbols.

    Example.  Given ``config.json``::

        {
          "constants": {"k1": 6.5e-5, "k2": 0.001},
          "subexprs":  {"power": "v*i"},
          "formula":   "0.5*power - k1*v**2 - k2*i**2"
        }

    compile and call::

        f = make_expr_func_from_json(
            "config.json",
            expr_at      = "formula",
            constants_at = "constants",
            subexprs_at  = "subexprs",
        )
        f(1.5, 220.0)                # auto-detected order: i, v

    Names should be disjoint across constants / subexprs / params; if
    they overlap, sub-expression definitions win over constant values
    (subexprs are inlined first).

    Precision
    ---------
    The JSON loader uses ``parse_float=str`` so floats arrive at
    :func:`_substitute_constants` as their original textual form.
    A constant written as ``0.833333333333`` (12 digits) is preserved
    exactly through to the generated code, instead of being rounded
    to Python's default 15-significant-digit display.  Beyond ~17
    digits the runtime is still bounded by IEEE-754 doubles — the
    digits past that survive in the generated source for traceability
    but the executed computation is double-precision.

    ``compile_opts`` are forwarded to :func:`make_expr_func`
    (``jit``, ``fastmath``, ``cache``, ``debug``).
    """
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh, parse_float=str)

    expr = get_at_path(data, expr_at)
    if not isinstance(expr, str):
        raise TypeError(f"expr at {expr_at!r} must be a string, "
                        f"got {type(expr).__name__}")

    # Inline subexprs first — their resolved values may reference
    # constants, which then get substituted in the next step.
    if subexprs_at is not None:
        subexprs = get_at_path(data, subexprs_at)
        if not isinstance(subexprs, dict):
            raise TypeError(f"subexprs at {subexprs_at!r} must be a dict, "
                            f"got {type(subexprs).__name__}")
        if not all(isinstance(k, str) and isinstance(v, str)
                   for k, v in subexprs.items()):
            raise TypeError(f"subexprs at {subexprs_at!r} must map "
                            f"str -> str")
        expr = _expand_subexprs(expr, subexprs)

    if constants_at is not None:
        constants = get_at_path(data, constants_at)
        if not isinstance(constants, dict):
            raise TypeError(f"constants at {constants_at!r} must be a dict, "
                            f"got {type(constants).__name__}")
        expr = _substitute_constants(expr, constants)

    if params_at is not None:
        params: list[str] = []
        for path in _normalize_paths(params_at):
            chunk = get_at_path(data, path)
            if not (isinstance(chunk, list)
                    and all(isinstance(p, str) for p in chunk)):
                raise TypeError(f"params at {path!r} must be a list of "
                                f"strings, got {type(chunk).__name__}")
            params.extend(chunk)
    else:
        params = _detect_params(expr)

    return make_expr_func(expr, params, **compile_opts)


def compile_expressions_in_data(data, is_expr, **compile_opts):
    """Walk a JSON-like nested structure (dicts, lists, primitives)
    and compile only the leaves identified by ``is_expr`` as math
    expressions.  Returns a NEW structure mirroring ``data`` with
    matched leaves replaced by callables; everything else passes
    through unchanged.

    Parameters
    ----------
    data : dict | list | scalar
        Anything ``json.load`` can produce.  Walked recursively.
    is_expr : callable(path, value) -> bool
        Predicate run on every leaf.  ``path`` is a tuple of dict keys
        (str) and list indices (int) leading to the value; ``value``
        is the leaf itself.  Return True iff the leaf is a math
        expression that should be compiled.
    **compile_opts
        Forwarded to :func:`make_expr_func` (``jit``, ``fastmath``,
        ``cache``, ``debug``).

    Useful predicate shapes::

        # Any string under a key named "formula" / "expr":
        lambda p, v: isinstance(v, str) and p and p[-1] in ("formula", "expr")

        # Sentinel-prefix convention "=expression":
        lambda p, v: isinstance(v, str) and v.startswith("=")
        # (then strip the "=" yourself before passing to make_expr_func —
        #  or use the load_expressions_from_json marker= helper below)

        # Specific paths only:
        lambda p, v: p == ("device", "transfer_func")

        # Nested under a "formulas" subtree, regardless of inner key:
        lambda p, v: isinstance(v, str) and len(p) >= 1 and p[0] == "formulas"

    Returned structure example::

        in:  {"name": "x", "max_v": 220,
              "calc": {"f": "a*b + c"}, "schedule": [{"v": "x*2"}]}
        out: {"name": "x", "max_v": 220,
              "calc": {"f": <fn(a,b,c)>}, "schedule": [{"v": <fn(x)>}]}
    """
    def _walk(node, path):
        if isinstance(node, dict):
            return {k: _walk(v, path + (k,)) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v, path + (i,)) for i, v in enumerate(node)]
        if is_expr(path, node):
            if not isinstance(node, str):
                raise TypeError(
                    f"is_expr returned True for non-string at path {path!r}: "
                    f"{type(node).__name__} (only strings can be compiled)")
            params = _detect_params(node)
            return make_expr_func(node, params, **compile_opts)
        return node

    return _walk(data, ())


def load_expressions_from_json(json_path: str | Path, is_expr,
                               **compile_opts):
    """Convenience: open ``json_path``, parse, walk via
    :func:`compile_expressions_in_data`, return the compiled
    structure."""
    with Path(json_path).open(encoding='utf-8') as fh:
        data = json.load(fh)
    return compile_expressions_in_data(data, is_expr, **compile_opts)


def make_funcs_from_json(json_path: str | Path, **compile_opts) -> dict:
    """Read formulas from a JSON file and compile each one.

    Returns a ``{name: callable}`` mapping.  ``compile_opts`` are
    forwarded to :func:`make_expr_func` (``jit``, ``fastmath``,
    ``cache``, ``debug``).

    Two JSON layouts are supported and may be mixed in a single file:

    1. **Flat** — name keys map directly to expression strings.
       Parameter order is auto-detected alphabetically from each
       expression::

           {
               "torque":   "0.5 * m * r**2 * omega",
               "voltage":  "I * R + L * dI_dt"
           }

    2. **Detailed** — name keys map to objects with an ``expr`` field
       and an optional ``params`` field that controls positional
       argument order::

           {
               "torque": {
                   "expr":   "0.5 * m * r**2 * omega",
                   "params": ["m", "r", "omega"]
               }
           }

       Use the detailed form when you need a non-alphabetical arg
       order, or when a variable's name collides with a sympy
       constant (``E``, ``I``, ``pi`` …) and auto-detection would
       miss it.

    Raises ``ValueError`` / ``TypeError`` on a malformed file with a
    message identifying the offending entry.
    """
    path = Path(json_path)
    with path.open(encoding='utf-8') as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise TypeError(f"{path}: top-level JSON must be an object, "
                        f"got {type(data).__name__}")

    funcs: dict = {}
    for name, entry in data.items():
        if isinstance(entry, str):
            expr_str = entry
            params = _detect_params(expr_str)
        elif isinstance(entry, dict) and 'expr' in entry:
            expr_str = entry['expr']
            if not isinstance(expr_str, str):
                raise TypeError(f"{name}: 'expr' must be a string, "
                                f"got {type(expr_str).__name__}")
            params = entry.get('params')
            if params is None:
                params = _detect_params(expr_str)
            elif not (isinstance(params, list)
                      and all(isinstance(p, str) for p in params)):
                raise TypeError(f"{name}: 'params' must be a list of strings")
        else:
            raise TypeError(
                f"{name}: entry must be either an expression string or an "
                f"object with an 'expr' field, got {type(entry).__name__}")

        funcs[name] = make_expr_func(expr_str, params, **compile_opts)

    return funcs


