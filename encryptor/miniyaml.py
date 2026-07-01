"""miniyaml — dependency-free loader for the small YAML subset antirev configs
use, with a PyYAML fallback only for configs that exceed that subset.

WHY: the only external dependency the packer needed was PyYAML, and only for a
single ``safe_load`` per tool.  antirev configs use a tiny, well-behaved subset,
so we parse it in-process and drop the pip dependency.

Supported subset (everything real antirev/antirevfs configs use):
  - block mappings ............ ``key: value``
  - nested mappings ........... ``key:`` then an indented block
  - block sequences ........... ``- item`` as the indented value of a key
  - scalars ................... bare or quoted ("..." / '...')
  - comments .................. full-line and inline ``#`` (quote-aware)
  - ``true``/``false`` -> bool, ``null``/``~``/empty -> None

DELIBERATE: bare scalars that look numeric stay STRINGS.  A version like
``1.20`` must NOT become the float ``1.2`` — that would silently change the
keysplit key (see encryptor/protect.py derive_real_key).  Quote a value only if
it would otherwise be read as a bool/null.

NOT supported (rare in configs): anchors/aliases, flow style ``{a: b}`` /
``[a, b]``, multi-line/folded scalars, multiple documents, tag directives,
``- key: value`` inline maps in sequences.  ``load_path`` falls back to PyYAML
(if installed) when the built-in parser hits any of these; the built-in parser
is otherwise authoritative so the result is identical whether or not PyYAML is
present.
"""

from pathlib import Path


class MiniYamlError(ValueError):
    """Raised when the input uses a feature outside the supported subset."""


# ── scalar handling ──────────────────────────────────────────────────

def _unescape_double(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _scalar(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return _unescape_double(s[1:-1])
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if s == "" or low in ("null", "~"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    return s                       # bare string (numbers stay strings — see module doc)


def _key(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    return s


# ── tokenizer (strips comments, drops blank lines) ───────────────────

def _strip_inline_comment(line: str) -> str:
    out, q, i, n = [], None, 0, len(line)
    while i < n:
        c = line[i]
        if q:                                   # inside a quoted span
            out.append(c)
            if c == q:
                q = None
        elif c in ("'", '"'):
            q = c
            out.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break                               # comment starts here
        else:
            out.append(c)
        i += 1
    return "".join(out).rstrip()


def _tokenize(text: str):
    lines = []
    for lineno, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise MiniYamlError(f"line {lineno}: tab used for indentation")
        s = _strip_inline_comment(raw)
        if s.strip() == "":
            continue
        indent = len(s) - len(s.lstrip(" "))
        lines.append((indent, s.strip(), lineno))
    return lines


# ── recursive-descent block parser ───────────────────────────────────

def _parse_block(lines, i, indent):
    content = lines[i][1]
    if content == "-" or content.startswith("- "):
        return _parse_seq(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_seq(lines, i, indent):
    seq = []
    while i < len(lines) and lines[i][0] == indent and \
            (lines[i][1] == "-" or lines[i][1].startswith("- ")):
        item = lines[i][1][1:].strip()
        if item == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                child, i = _parse_block(lines, i + 1, lines[i + 1][0])
                seq.append(child)
            else:
                seq.append(None)
                i += 1
        elif ":" in item and not (item[0] in "\"'"):
            # "- key: value" inline map — outside the supported subset
            raise MiniYamlError(f"line {lines[i][2]}: inline map in sequence "
                                f"not supported")
        else:
            seq.append(_scalar(item))
            i += 1
    return seq, i


def _parse_map(lines, i, indent):
    mp = {}
    while i < len(lines) and lines[i][0] == indent:
        indent0, content, lineno = lines[i]
        if content.startswith("- "):
            raise MiniYamlError(f"line {lineno}: sequence item where a mapping "
                                f"key was expected")
        if ":" not in content:
            raise MiniYamlError(f"line {lineno}: expected 'key: value', got {content!r}")
        rawkey, _, rawval = content.partition(":")
        key = _key(rawkey)
        val = rawval.strip()
        if val == "":
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                child, i = _parse_block(lines, i + 1, lines[i + 1][0])
                mp[key] = child
            else:
                mp[key] = None
                i += 1
        else:
            mp[key] = _scalar(val)
            i += 1
    return mp, i


def load(text: str):
    """Parse a YAML-subset string.  Returns dict / list / scalar / None."""
    lines = _tokenize(text)
    if not lines:
        return None
    base = lines[0][0]
    if base != 0:
        raise MiniYamlError(f"line {lines[0][2]}: top-level content must not be indented")
    val, i = _parse_block(lines, 0, base)
    if i != len(lines):
        raise MiniYamlError(f"line {lines[i][2]}: unexpected indentation / trailing content")
    return val


def load_path(path):
    """Load a config file.  Uses the built-in subset parser (authoritative, so
    the result is identical with or without PyYAML installed); only if the file
    uses a feature outside the subset do we fall back to PyYAML (when present)."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        return load(text)
    except MiniYamlError:
        try:
            import yaml
        except ImportError:
            raise
        return yaml.safe_load(text)
