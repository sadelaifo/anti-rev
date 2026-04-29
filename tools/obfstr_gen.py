#!/usr/bin/env python3
"""obfstr_gen.py — compile-time string-literal obfuscation pass.

Scans the input C sources for calls to a fixed set of macros (OBFSTR,
LOG_ERR, PERR, OSNPRINTF, ODLSYM ...) and rewrites the string-literal
argument(s) into pre-encrypted byte sequences `_OBF(0xab, 0xcd, ...)`.
The encryption key matches stub/obfstr.h, which decrypts the bytes back
into a stack buffer at runtime.

Usage:
    obfstr_gen.py --out-dir <build-dir/obf> <src.c> [<src.c> ...]

For every input src.c we write build-dir/obf/<basename>.c with the
literals replaced.  Headers are not transformed (literals in headers
that get preprocessed into a .c are visible after preprocessing — but
the codegen runs *before* the preprocessor, so we only catch literals
written directly in the .c sources we're given).
"""

import argparse
import os
import re
import sys

# Macros whose calls we scan.  At each call site we walk every
# positional argument; any one that parses as a string-literal (or as
# concatenated string-literals) is replaced with an encrypted _OBF(...)
# byte sequence.  Non-literal arguments (variables, expressions, char
# literals) are left untouched.  This means e.g.
#     LOG_ERR("hello %s", "world")
# obfuscates BOTH the format and the string passed via %s, which is
# what we want for "tier 3 — no literal survives in rodata".
TRANSFORM_MACROS = (
    'OBFSTR',
    'LOG_ERR',
    'PERR',
    'OSNPRINTF',
    'ODLSYM',
)

# ---------------------------------------------------------------------
# Key derivation — must match _OBF_K() in stub/obfstr.h byte-for-byte.
# ---------------------------------------------------------------------
def obf_key(i: int) -> int:
    return 0x5a ^ (((i * 7) + 13) & 0xff)


def encode_bytes(s: bytes) -> str:
    """Return a comma-separated hex byte list ready to splice into the
    _OBF(...) macro: e.g. b'hi' → '0x32, 0x2c'."""
    return ', '.join(f'0x{(b ^ obf_key(i)) & 0xff:02x}' for i, b in enumerate(s))


# ---------------------------------------------------------------------
# Source scanner — find calls to TRANSFORM_MACROS, extract the relevant
# argument, replace if it's a string-literal.
# ---------------------------------------------------------------------

# Identifier preceded by non-identifier (or beginning of string) and
# followed by '(' — narrows to "macro call" (vs. e.g. comments).
_macro_pat = re.compile(r'(?<![A-Za-z0-9_])(' + '|'.join(re.escape(m) for m in TRANSFORM_MACROS) + r')\s*\(')

_TRANSFORM_SET = set(TRANSFORM_MACROS)


def find_matching_paren(src: str, open_pos: int) -> int:
    """Given that src[open_pos] == '(', return the index of the matching
    ')' or -1 if unbalanced.  Handles nested parens, string-literals,
    char-literals, and // and /* */ comments inside the call."""
    depth = 0
    i = open_pos
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n:
            nxt = src[i + 1]
            if nxt == '/':
                # line comment, skip to newline
                j = src.find('\n', i)
                i = (j + 1) if j >= 0 else n
                continue
            if nxt == '*':
                j = src.find('*/', i + 2)
                if j < 0:
                    return -1
                i = j + 2
                continue
        if c == '"':
            # string literal — skip including escapes
            i += 1
            while i < n and src[i] != '"':
                if src[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
            continue
        if c == "'":
            # char literal
            i += 1
            while i < n and src[i] != "'":
                if src[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def split_args(args_text: str):
    """Split a macro argument list at top-level commas.  Returns a list
    of (start_offset_in_args_text, end_offset_in_args_text, raw_text)
    tuples.  Comments + nested parens + string/char-literals are
    respected."""
    out = []
    depth = 0
    n = len(args_text)
    i = 0
    arg_start = 0
    while i < n:
        c = args_text[i]
        if c == '/' and i + 1 < n:
            nxt = args_text[i + 1]
            if nxt == '/':
                j = args_text.find('\n', i)
                i = (j + 1) if j >= 0 else n
                continue
            if nxt == '*':
                j = args_text.find('*/', i + 2)
                i = (j + 2) if j >= 0 else n
                continue
        if c == '"':
            i += 1
            while i < n and args_text[i] != '"':
                if args_text[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
            continue
        if c == "'":
            i += 1
            while i < n and args_text[i] != "'":
                if args_text[i] == '\\' and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i += 1
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            out.append((arg_start, i, args_text[arg_start:i]))
            arg_start = i + 1
        i += 1
    if arg_start < n or n > 0:
        out.append((arg_start, n, args_text[arg_start:n]))
    return out


# Pull out the bytes from a sequence of C string-literal tokens, with
# trivial concatenation: "a" "b" → b'ab'.  Returns None if the argument
# contains anything other than string literals.
_str_token = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*')

# C escape sequences we accept inside string literals.
_escape_map = {
    'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f', 'v': '\v',
    'a': '\a', '\\': '\\', '"': '"', "'": "'", '?': '?', '0': '\0',
}


def parse_string_literal_arg(arg_text: str):
    """If arg_text is exactly a sequence of one or more C string-literals
    (optionally wide/u8 — we reject those for safety), return the decoded
    bytes; otherwise None."""
    pos = 0
    n = len(arg_text)

    # Strip leading whitespace
    while pos < n and arg_text[pos] in ' \t\r\n':
        pos += 1
    if pos >= n:
        return None

    # Reject any encoding prefix to keep the decoder simple
    if arg_text[pos] in 'uULu':
        # Could be a string-literal prefix (L, u, U, u8) — refuse to obfuscate
        # any non-narrow string.  Easier than supporting wide chars.
        return None

    if arg_text[pos] != '"':
        return None

    out = bytearray()
    while pos < n:
        # Skip whitespace and comments between concatenated literals
        while pos < n:
            ch = arg_text[pos]
            if ch in ' \t\r\n':
                pos += 1
                continue
            if ch == '/' and pos + 1 < n and arg_text[pos + 1] == '/':
                j = arg_text.find('\n', pos)
                pos = (j + 1) if j >= 0 else n
                continue
            if ch == '/' and pos + 1 < n and arg_text[pos + 1] == '*':
                j = arg_text.find('*/', pos + 2)
                if j < 0:
                    return None
                pos = j + 2
                continue
            break

        if pos >= n:
            break
        if arg_text[pos] != '"':
            # Anything other than another concatenated literal → reject
            return None

        # Decode this literal
        pos += 1  # skip opening "
        while pos < n and arg_text[pos] != '"':
            ch = arg_text[pos]
            if ch == '\\' and pos + 1 < n:
                esc = arg_text[pos + 1]
                if esc in _escape_map:
                    out.append(ord(_escape_map[esc]))
                    pos += 2
                elif esc == 'x':
                    # \xHH...  — read up to 2 hex digits
                    pos += 2
                    hex_start = pos
                    while pos < n and arg_text[pos] in '0123456789abcdefABCDEF' and pos - hex_start < 2:
                        pos += 1
                    if pos == hex_start:
                        return None
                    out.append(int(arg_text[hex_start:pos], 16) & 0xff)
                elif esc.isdigit():
                    # \ooo — up to 3 octal digits
                    oct_start = pos + 1
                    pos = oct_start
                    while pos < n and arg_text[pos] in '01234567' and pos - oct_start < 3:
                        pos += 1
                    out.append(int(arg_text[oct_start:pos], 8) & 0xff)
                else:
                    # Unknown escape — bail out to be safe
                    return None
            else:
                out.append(ord(ch))
                pos += 1
        if pos >= n:
            return None  # unterminated literal
        pos += 1  # skip closing "

    # Strip trailing whitespace; anything else → reject
    while pos < n and arg_text[pos] in ' \t\r\n':
        pos += 1
    if pos != n:
        return None
    return bytes(out)


def transform_source(src: str) -> str:
    """Walk `src` left to right, find every macro call we know about,
    and rewrite the string-literal argument(s) in place."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        m = _macro_pat.search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        macro = m.group(1)
        open_paren = m.end() - 1
        close_paren = find_matching_paren(src, open_paren)
        if close_paren < 0:
            # Unbalanced — emit verbatim
            out.append(src[m.start():])
            break

        args_text = src[open_paren + 1:close_paren]
        args = split_args(args_text)

        new_args = list(args)
        any_replaced = False
        # Scan every positional arg; any string-literal arg gets
        # obfuscated, others passed through unchanged.
        for ti in range(len(args)):
            arg_start, arg_end, arg_raw = args[ti]
            decoded = parse_string_literal_arg(arg_raw)
            if decoded is None:
                continue
            replacement = '_OBF(' + encode_bytes(decoded) + ')' if decoded else '_OBF()'
            # Preserve any leading whitespace from the original arg so the
            # rewritten source still looks vaguely tidy.
            lead = ''
            for ch in arg_raw:
                if ch in ' \t\r\n':
                    lead += ch
                else:
                    break
            new_args[ti] = (arg_start, arg_end, lead + replacement)
            any_replaced = True

        if any_replaced:
            rebuilt = ','.join(a[2] for a in new_args)
            out.append(macro + '(' + rebuilt + ')')
        else:
            out.append(src[m.start():close_paren + 1])
        i = close_paren + 1
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir', required=True,
                    help='directory to write transformed sources into')
    ap.add_argument('sources', nargs='+', help='C source files to transform')
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    for src_path in args.sources:
        with open(src_path, 'r', encoding='utf-8') as f:
            src = f.read()
        transformed = transform_source(src)
        # Mark transformed files so anyone reading them knows what's up.
        # Fall back to absolute path on Windows when src and cwd live on
        # different drives (relpath raises ValueError there).
        try:
            origin = os.path.relpath(src_path)
        except ValueError:
            origin = os.path.abspath(src_path)
        banner = (f'/* AUTO-GENERATED by tools/obfstr_gen.py — DO NOT EDIT.\n'
                  f' * Original: {origin}\n'
                  f' */\n')
        out_path = os.path.join(args.out_dir, os.path.basename(src_path))
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(banner + transformed)
        print(f'[obfstr_gen] {src_path} -> {out_path}')


if __name__ == '__main__':
    main()
