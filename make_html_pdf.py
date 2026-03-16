"""Generate antirev presentation as HTML then PDF via WeasyPrint."""

import weasyprint

# ── Colour palette (same as make_ppt.py) ─────────────────────────────────────
BG       = "#0D1B2A"
ACCENT   = "#00B4D8"
ACCENT2  = "#F77F00"
WHITE    = "#FFFFFF"
LIGHT    = "#CAD3DF"
GREEN    = "#06D6A0"
RED      = "#EF476F"
GREY_BG  = "#1A2B3C"
CARD_BG  = "#122435"

# ── Slide dimensions: 16:9 at 96 dpi → 1280×720 px ───────────────────────────
SW, SH = 1280, 720

CSS = f"""
@page {{
    size: {SW}px {SH}px;
    margin: 0;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'Segoe UI', 'DejaVu Sans', Arial, sans-serif;
    background: {BG};
    color: {WHITE};
}}
.slide {{
    width: {SW}px;
    height: {SH}px;
    background: {BG};
    position: relative;
    overflow: hidden;
    page-break-after: always;
}}
/* ── top accent bar ── */
.top-bar {{
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 7px;
    background: {ACCENT};
}}
.bot-bar {{
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 7px;
    background: {ACCENT};
}}
/* ── slide header ── */
.slide-header {{
    position: absolute;
    top: 14px; left: 44px; right: 44px;
}}
.slide-header .title {{
    font-size: 26px;
    font-weight: 700;
    color: {WHITE};
    line-height: 1.15;
}}
.slide-header .subtitle {{
    font-size: 13px;
    color: {ACCENT};
    font-style: italic;
    margin-top: 2px;
}}
/* ── cards ── */
.card {{
    position: absolute;
    border-radius: 4px;
    padding: 14px 16px;
}}
.card-accent  {{ border: 1px solid {ACCENT};  background: {CARD_BG}; }}
.card-accent2 {{ border: 1px solid {ACCENT2}; background: {CARD_BG}; }}
.card-green   {{ border: 1px solid {GREEN};   background: {CARD_BG}; }}
.card-red     {{ border: 1px solid {RED};     background: {CARD_BG}; }}
.card-grey    {{ border: 1px solid #204060;   background: {GREY_BG}; }}
.card-dark    {{ border: 1px solid #505080;   background: {CARD_BG}; }}
.card-title   {{ font-size: 13px; font-weight: 700; margin-bottom: 7px; }}
.card-body    {{ font-size: 11.5px; line-height: 1.55; color: {LIGHT}; }}
.card-body .green {{ color: {GREEN}; }}
.card-body .red   {{ color: {RED}; }}
.card-body .dim   {{ color: #90A8BB; margin-left: 16px; display: block; }}
/* ── step table rows ── */
.step-row {{
    display: flex;
    align-items: stretch;
    margin-bottom: 1px;
}}
.step-num {{
    width: 38px; min-width: 38px;
    background: {ACCENT};
    color: {BG};
    font-weight: 700;
    font-size: 15px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
}}
.step-head {{
    width: 215px; min-width: 215px;
    background: {GREY_BG};
    border: 1px solid #204060;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 700;
    color: {ACCENT2};
    display: flex; align-items: center;
    flex-shrink: 0;
}}
.step-desc {{
    flex: 1;
    background: {CARD_BG};
    border: 1px solid #204060;
    padding: 5px 10px;
    font-size: 10.5px;
    color: {LIGHT};
    display: flex; align-items: center;
}}
/* ── use-table rows ── */
.use-row {{
    display: flex;
    align-items: stretch;
    margin-bottom: 1px;
}}
.use-head {{
    width: 200px; min-width: 200px;
    background: {GREY_BG};
    border: 1px solid #204060;
    padding: 6px 10px;
    font-size: 11px; font-weight: 700;
    color: {ACCENT2};
    display: flex; align-items: center;
    flex-shrink: 0;
}}
.use-cmd {{
    width: 390px; min-width: 390px;
    background: #05101A;
    border: 1px solid #204060;
    padding: 6px 10px;
    font-size: 9.5px; font-family: monospace;
    color: {GREEN};
    display: flex; align-items: center;
    white-space: pre-wrap;
    flex-shrink: 0;
}}
.use-desc {{
    flex: 1;
    background: {CARD_BG};
    border: 1px solid #204060;
    padding: 6px 10px;
    font-size: 10.5px; color: {LIGHT};
    display: flex; align-items: center;
}}
/* ── bundle format table ── */
.bundle-table {{ width: 100%; border-collapse: collapse; font-size: 10.5px; }}
.bundle-table td {{ padding: 3px 8px; border: 1px solid #305070; }}
.bundle-table .name {{ color: {LIGHT}; }}
.bundle-table .size {{ color: {ACCENT2}; text-align: right; }}
/* ── info banner ── */
.banner {{
    position: absolute;
    background: #003A52;
    border: 1.5px solid {ACCENT};
    border-radius: 4px;
    padding: 10px 20px;
    font-size: 13px;
    color: {ACCENT};
    text-align: center;
}}
/* ── monospace code inline ── */
code {{
    font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
    font-size: 0.92em;
    color: {GREEN};
}}
"""

# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def slide_open(extra_style=""):
    return f'<div class="slide" style="{extra_style}"><div class="top-bar"></div>'

def slide_close():
    return '</div>\n'

def header(title, subtitle=None):
    sub = f'<div class="subtitle">{subtitle}</div>' if subtitle else ""
    return f'<div class="slide-header"><div class="title">{title}</div>{sub}</div>'

def card(cls, title, items, left, top, width, height,
         title_color=None, item_size=None):
    tc = f'color:{title_color};' if title_color else ""
    sz = f'font-size:{item_size}px;' if item_size else ""
    rows = []
    for item in items:
        if item == "":
            rows.append('<span style="display:block;height:5px;"></span>')
            continue
        col = LIGHT
        extra = ""
        indent = ""
        label = item
        if label.startswith("  "):
            indent = "margin-left:14px;"
            label = label.lstrip()
            col = "#90A8BB"
        if label.startswith("✓"):
            col = GREEN
        elif label.startswith("✗"):
            col = RED
        rows.append(
            f'<span style="display:block;{indent}color:{col};{sz}">{label}</span>'
        )
    body = "".join(rows)
    t = f'<div class="card-title" style="{tc}">{title}</div>' if title else ""
    return (
        f'<div class="{cls}" style="left:{left}px;top:{top}px;'
        f'width:{width}px;height:{height}px;">'
        f'{t}<div class="card-body">{body}</div></div>'
    )

# ─────────────────────────────────────────────────────────────────────────────
# SLIDES
# ─────────────────────────────────────────────────────────────────────────────

slides = []

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 1 — Title
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += '<div class="top-bar" style="height:12px;"></div>'
s += '<div class="bot-bar" style="height:12px;"></div>'
s += f'''
<div style="position:absolute;top:0;left:0;right:0;bottom:0;
     display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;">
  <div style="font-size:74px;font-weight:900;color:{WHITE};letter-spacing:4px;line-height:1;">AntiRev</div>
  <div style="font-size:22px;color:{ACCENT};font-weight:600;">ELF Binary Protection &mdash; Technical Overview</div>
  <div style="font-size:14px;color:{LIGHT};font-style:italic;">
    Encryption &middot; In-Memory Execution &middot; Dynamic Library Interception</div>
  <div style="font-size:12px;color:{LIGHT};margin-top:24px;">March 2026</div>
</div>
'''
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 2 — Problem Statement
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Problem Statement", "What are we protecting against?")

problems = [
    "• Static analysis (Ghidra, IDA Pro, objdump) can fully decompile any standard ELF",
    "• Custom shared libraries (.so) loaded via dlopen() are equally exposed on disk",
    "• No source-level changes to the target software are acceptable",
    "• Decryption key must NOT be stored statically in the binary (license enforcement)",
    "• Zero disk writes at runtime — decrypted content must never touch the filesystem",
]
goals = [
    "• Opaque binary on disk — no decompiler recovers meaningful code",
    "• Transparent execution — software runs identically, same PID, same argv",
    "• All custom .so files also encrypted and intercepted seamlessly",
    "• Key fetched from license server at runtime (future)",
    "• x86-64 and ARM64 support",
]
s += card("card-accent card-red", "Threats &amp; Constraints", problems,
          34, 120, 590, 340, title_color=RED, item_size=12)
s += card("card-accent card-green", "Goals", goals,
          666, 120, 590, 340, title_color=GREEN, item_size=12)

s += f'''
<div class="banner" style="left:34px;right:34px;bottom:48px;">
  Requirement: protect compiled binaries with no modifications to source or build system
</div>'''
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 3 — Encryption Options
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Encryption Algorithm Options", "Comparing candidates for binary-file encryption")

COL_W = 388
COL_H = 510
Y0    = 124

aes_items = [
    "✓ AEAD — confidentiality + integrity",
    "✓ Hardware AES-NI on x86-64 &amp; ARMv8",
    "✓ FIPS 140-2 compliant",
    "✓ Widely supported (OpenSSL, BoringSSL)",
    "✗ GCM nonce reuse is catastrophic",
    "✗ Slightly more complex API than CTR",
    "",
    "Verdict: chosen — best hw-accel + auth",
]
cc_items = [
    "✓ AEAD — same security guarantees",
    "✓ Faster on CPUs without AES-NI",
    "✓ Immune to timing side-channels",
    "✓ TLS 1.3 standard cipher",
    "✗ Slower on modern x86 with AES-NI",
    "✗ Less common in embedded/RTOS libs",
    "",
    "Verdict: valid alternative for ARM cores without crypto extensions",
]
cbc_items = [
    "✓ Universally supported",
    "✓ Simple implementation",
    "✗ No authentication — malleable",
    "✗ Requires separate HMAC layer",
    "✗ Padding oracle attacks possible",
    "✗ Does not detect tampering",
    "",
    "Verdict: rejected — no integrity check",
]
s += card("card-green", "AES-256-GCM", aes_items, 28, Y0, COL_W, COL_H,
          title_color=GREEN, item_size=12)
s += card("card-accent", "ChaCha20-Poly1305", cc_items, 446, Y0, COL_W, COL_H,
          title_color=ACCENT, item_size=12)
s += card("card-red", "AES-256-CBC", cbc_items, 864, Y0, COL_W, COL_H,
          title_color=RED, item_size=12)
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 4 — Decision
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Encryption Decision", "Why AES-256-GCM was selected")
s += f'''
<div class="banner" style="left:34px;top:110px;right:34px;height:52px;font-size:15px;font-weight:700;
     display:flex;align-items:center;justify-content:center;">
  Selected: AES-256-GCM &nbsp;|&nbsp; Key size: 256-bit &nbsp;|&nbsp; IV: 96-bit random per file &nbsp;|&nbsp; Tag: 128-bit
</div>'''

reasons = [
    "• <b>AEAD cipher</b> — a single primitive provides both confidentiality and tamper detection.",
    "  → If ciphertext is bit-flipped (tampering/corruption), GCM tag verification fails and the binary is rejected.",
    "• <b>AES-NI hardware acceleration</b> available on all modern x86-64 and ARMv8 cores.",
    "  → Decryption of a 10 MB ELF takes &lt; 5 ms even on modest hardware.",
    "• <b>Random 96-bit IV</b> generated per file by protect.py — nonce reuse eliminated by design.",
    "• <b>OpenSSL EVP API</b> used — portable across Linux distributions, already available via Node.js bundled libs.",
    "• <b>FIPS 140-2</b> compliance relevant for future enterprise/government deployments.",
    "• One key (256-bit) per protected binary — future upgrade path to per-machine keys from license server.",
]
s += card("card-accent", "Rationale", reasons, 34, 178, 1212, 480,
          title_color=ACCENT, item_size=12)
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 5 — How Binary Encryption Works
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("How Binary Encryption Works", "Offline protect.py tool — build-time step")

steps_enc = [
    "1.  Read input ELF (main binary) + any .so files",
    "2.  Generate or load 256-bit AES key from key file",
    "3.  For each file:",
    "      Generate random 96-bit IV",
    "      AES-256-GCM encrypt → ciphertext + 128-bit tag",
    "4.  Serialise all entries into bundle format",
    "5.  Append bundle after stub ELF bytes",
    "6.  Append 48-byte trailer (bundle offset + key + magic)",
    "7.  Write protected binary → chmod +x",
]
s += card("card-accent", "protect.py — offline steps", steps_enc,
          28, 120, 560, 500, title_color=ACCENT, item_size=12)

# bundle table on the right
bundle_rows = [
    ("num_files", "4B LE",   GREY_BG),
    ("name_len + name", "var", CARD_BG),
    ("flags (bit0=is_main)", "1B", GREY_BG),
    ("IV", "12B", CARD_BG),
    ("GCM tag", "16B", GREY_BG),
    ("ciphertext size", "8B LE", CARD_BG),
    ("ciphertext", "N bytes", GREY_BG),
    ("↑ repeated per file", "", BG),
    ("bundle_start_offset", "8B LE", "#1A3A1A"),
    ("AES-256 key", "32B", "#3A1A00"),
    ("magic ANTREV01", "8B", "#2A002A"),
]
trows = ""
for label, size, bg in bundle_rows:
    trows += (
        f'<tr><td class="name" style="background:{bg};">{label}</td>'
        f'<td class="size" style="background:{bg};">{size}</td></tr>'
    )
s += f'''
<div style="position:absolute;left:620px;top:120px;width:630px;">
  <div style="font-size:12px;font-weight:700;color:{ACCENT};margin-bottom:6px;
       background:{CARD_BG};border:1px solid {ACCENT};padding:6px 10px;border-radius:3px 3px 0 0;">
    BUNDLE FORMAT (appended to stub ELF)
  </div>
  <table class="bundle-table" style="width:100%;background:{CARD_BG};border:1px solid {ACCENT};">
    {trows}
  </table>
  <div style="font-size:10px;color:{ACCENT2};text-align:right;margin-top:3px;">← 48-byte trailer (last 3 rows)</div>
</div>
'''
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 6 — Runtime Flow
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Runtime Flow", "How the stub decrypts and launches the protected binary")

steps_rt = [
    ("1", "Open /proc/self/exe",  "Read last 48 bytes → verify ANTREV01 magic → extract bundle_start_offset and AES key"),
    ("2", "Read bundle",          "pread() full bundle into malloc'd RAM buffer"),
    ("3", "Decrypt files",        "For each entry: AES-256-GCM decrypt → verify GCM tag → abort if tampered"),
    ("4", "Write to memfds",      "memfd_create() per file → write plaintext → seek back to 0. File never touches disk."),
    ("5", "Wipe secrets",         "explicit_bzero(key) + explicit_bzero(bundle buffer) — key gone from RAM"),
    ("6", "Build LD_PRELOAD",     "Write dlopen_shim.so (embedded blob) to its own memfd → set LD_PRELOAD=/proc/self/fd/N"),
    ("7", "Build env map",        "ANTIREV_FD_MAP=libfoo.so=&lt;fd&gt;,libbar.so=&lt;fd&gt;,..."),
    ("8", "fexecve(main_fd,...)", "Replace process image in-place — same PID, no fork, no disk. Done."),
]
s += '<div style="position:absolute;left:34px;top:120px;right:34px;">'
for num, head, desc in steps_rt:
    s += f'''
    <div class="step-row">
      <div class="step-num">{num}</div>
      <div class="step-head">{head}</div>
      <div class="step-desc">{desc}</div>
    </div>'''
s += '</div>'
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 7 — dlopen / .so Interception
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Handling dlopen &amp; Encrypted .so Files",
            "How custom shared libraries are intercepted at runtime")

problem_items = [
    "• Target binary calls dlopen(\"libfoo.so\") at runtime",
    "• Standard dlopen searches filesystem — encrypted file on disk is useless",
    "• We cannot modify the target binary's source",
    "• Solution: intercept dlopen() via LD_PRELOAD before it hits the filesystem",
]
s += card("card-red", "The Problem", problem_items, 34, 112, 1212, 160,
          title_color=RED, item_size=12)

shim_items = [
    "• Small C shared library compiled for each target arch",
    "• Embedded as byte array in stub (dlopen_shim_blob.h)",
    "• Wraps dlopen() symbol — runs before libc's version",
    "• At startup: parses ANTIREV_FD_MAP env var into hash map",
    "• On each dlopen(name) call:",
    "  → If name in map: open /proc/self/fd/&lt;N&gt; instead",
    "  → Otherwise: forward to real dlopen unchanged",
]
s += card("card-accent", "dlopen_shim.so", shim_items, 34, 294, 560, 370,
          title_color=ACCENT, item_size=11.5)

env_items = [
    "Set by stub before fexecve():",
    "",
    "LD_PRELOAD=",
    "  /proc/self/fd/&lt;shim_fd&gt;",
    "",
    "ANTIREV_FD_MAP=",
    "  libfoo.so=&lt;fd_A&gt;,",
    "  libbar.so=&lt;fd_B&gt;",
    "",
    "• shim memfd never appears in /proc/pid/maps by filename",
    "• .so memfds are anonymous — not visible as files",
]
s += card("card-accent2", "Environment Variables", env_items, 618, 294, 290, 370,
          title_color=ACCENT2, item_size=11)

result_items = [
    "✓ dlopen() works transparently",
    "✓ No disk files for any .so",
    "✓ Zero source changes to target",
    "✓ Unknown .so names pass through",
    "✓ Works with multiple .so files",
    "✓ Shim itself lives in a memfd",
]
s += card("card-green", "Result", result_items, 932, 294, 314, 370,
          title_color=GREEN, item_size=12)
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 8 — Architecture Diagram
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Code Architecture", "Three-component design")

COMP_W = 376; COMP_H = 210; COMP_Y = 128

# protect.py
s += f'''
<div class="card card-accent2" style="left:28px;top:{COMP_Y}px;width:{COMP_W}px;height:{COMP_H}px;">
  <div class="card-title" style="color:{ACCENT2};">protect.py</div>
  <div class="card-body" style="font-size:11px;">
    <code>encryptor/protect.py</code><br><br>
    • Reads stub ELF binary<br>
    • Encrypts main ELF + .so files<br>
    • Serialises bundle format<br>
    • Appends bundle + trailer to stub<br>
    • Outputs protected binary
  </div>
</div>'''

# arrow label
s += f'''<div style="position:absolute;left:{28+COMP_W+2}px;top:{COMP_Y+COMP_H//2-18}px;
     width:54px;text-align:center;font-size:9px;color:{ACCENT2};">appends<br>bundle</div>'''

# stub
s += f'''
<div class="card card-accent" style="left:{28+COMP_W+58}px;top:{COMP_Y}px;width:{COMP_W}px;height:{COMP_H}px;">
  <div class="card-title" style="color:{ACCENT};">stub (launcher)</div>
  <div class="card-body" style="font-size:11px;">
    <code>stub/stub.c + stub/crypto.c</code><br><br>
    • Entry point of protected binary<br>
    • Reads + decrypts bundle from self<br>
    • Creates memfds, writes plaintext<br>
    • Wipes key from RAM<br>
    • fexecve() — replaces self
  </div>
</div>'''

arrow2x = 28 + COMP_W*2 + 58 + 2
s += f'''<div style="position:absolute;left:{arrow2x}px;top:{COMP_Y+COMP_H//2-18}px;
     width:54px;text-align:center;font-size:9px;color:{GREEN};">embedded<br>as blob</div>'''

# dlopen_shim
s += f'''
<div class="card card-green" style="left:{28+COMP_W*2+116}px;top:{COMP_Y}px;width:{COMP_W}px;height:{COMP_H}px;">
  <div class="card-title" style="color:{GREEN};">dlopen_shim.so</div>
  <div class="card-body" style="font-size:11px;">
    <code>stub/dlopen_shim.c</code><br><br>
    • Compiled per-arch → .so<br>
    • Converted to C byte-array header<br>
    • Embedded inside stub binary<br>
    • LD_PRELOAD'd into target process<br>
    • Intercepts dlopen() at runtime
  </div>
</div>'''

# Row 2
ROW2_Y = COMP_Y + COMP_H + 48

s += f'''
<div class="card card-dark" style="left:28px;top:{ROW2_Y}px;width:556px;height:175px;">
  <div class="card-title" style="color:{LIGHT};">CMakeLists.txt + cmake/</div>
  <div class="card-body" style="font-size:11px;">
    • Builds stub (x86-64) and stub_aarch64 (ARM64, static)<br>
    • Cross-compiles dlopen_shim.so for both arches via bin2h.py → header<br>
    • Test targets: run_test, test_dlopen, test_multi_so, test_wrong_key, test_tamper, run_tests
  </div>
</div>
<div class="card card-dark" style="left:610px;top:{ROW2_Y}px;right:28px;height:175px;">
  <div class="card-title" style="color:{LIGHT};">tests/</div>
  <div class="card-body" style="font-size:11px;">
    <code>tests/hello/</code> — simple ELF (prints hello + args)<br>
    <code>tests/dlopen/</code> — binary + mylib.so (tests shim)<br>
    <code>tests/multi_so/</code> — binary + libmath.so + libstr.so<br>
    Negative tests: wrong key → GCM fail; bit-flip → tag fail
  </div>
</div>'''

s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 9 — How to Use
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("How to Use AntiRev", "Step-by-step: protecting your ELF executable")

use_steps = [
    ("Build the toolchain",
     "cmake -B build && cmake --build build",
     "Builds stub (x86-64 + ARM64) and all test binaries."),
    ("Generate / obtain key",
     "python3 encryptor/protect.py --gen-key mykey.bin",
     "Outputs a 32-byte (256-bit) random key. Keep this file secure."),
    ("Protect main binary (no .so files)",
     "python3 encryptor/protect.py \\\n  --stub build/stub \\\n  --key mykey.bin \\\n  --main /path/to/your_app \\\n  --output your_app_protected",
     "Encrypts your_app, appends bundle to stub → outputs your_app_protected."),
    ("Protect binary with custom .so libraries",
     "python3 encryptor/protect.py \\\n  --stub build/stub \\\n  --key mykey.bin \\\n  --main /path/to/your_app \\\n  --so libfoo.so libbar.so \\\n  --output your_app_protected",
     "All listed .so files are also encrypted into the bundle. dlopen shim handles redirection."),
    ("Run protected binary",
     "./your_app_protected [original args...]",
     "Stub decrypts, memfds, wipes key, fexecve()s. Behaviour identical to unprotected binary."),
    ("Verify protection",
     "objdump -d your_app_protected   # stub only\nstrings  your_app_protected     # no readable strings",
     "Static analysis tools see only the small stub — your logic is not recoverable."),
]

s += '<div style="position:absolute;left:28px;top:112px;right:28px;">'
for head, cmd, desc in use_steps:
    s += f'''
    <div class="use-row">
      <div class="use-head">{head}</div>
      <div class="use-cmd">{cmd}</div>
      <div class="use-desc">{desc}</div>
    </div>'''
s += '</div>'

s += f'''
<div style="position:absolute;bottom:18px;left:28px;right:28px;
     font-size:11px;color:{ACCENT};font-style:italic;text-align:center;">
  Note: ANTIREV_KEY env var can override the embedded key (for testing without re-encrypting)
</div>'''
s += slide_close()
slides.append(s)

# ══════════════════════════════════════════════════════════════════════════════
# SLIDE 10 — Status & Roadmap
# ══════════════════════════════════════════════════════════════════════════════
s = slide_open()
s += header("Current Status &amp; Roadmap")

done = [
    "✓ AES-256-GCM encryption of main ELF + arbitrary .so files",
    "✓ All-RAM execution: memfd_create, zero disk writes",
    "✓ fexecve() in-place replacement — same PID, no fork",
    "✓ dlopen interception via embedded LD_PRELOAD shim",
    "✓ x86-64 and ARM64 (static) stub binaries",
    "✓ Key wiped from RAM immediately after decryption",
    "✓ 6 automated test targets (including 2 negative/tamper tests)",
]
todo = [
    "• License server integration: replace embedded key with HTTPS fetch at runtime",
    "• RT executable support: investigate load_elf() kernel API for memfd path compatibility",
    "• Anti-ptrace / anti-debug hardening (optional)",
    "• Per-machine key binding (hardware fingerprint tied to license)",
    "• Key rotation / revocation support",
]
s += card("card-green", "Done", done, 34, 120, 590, 400,
          title_color=GREEN, item_size=13)
s += card("card-accent2", "TODO / Roadmap", todo, 656, 120, 590, 400,
          title_color=ACCENT2, item_size=13)

s += f'''
<div class="banner" style="left:34px;right:34px;bottom:28px;height:66px;font-size:14px;
     display:flex;align-items:center;justify-content:center;">
  All six test targets pass on x86-64. ARM64 tests pass via QEMU binfmt transparent emulation.
</div>'''
s += slide_close()
slides.append(s)

# ─────────────────────────────────────────────────────────────────────────────
# Assemble HTML
# ─────────────────────────────────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AntiRev — Technical Overview</title>
<style>{CSS}</style>
</head>
<body>
{''.join(slides)}
</body>
</html>
"""

HTML_OUT = "/home/yz/Documents/anti-rev/antirev_overview.html"
PDF_OUT  = "/home/yz/Documents/anti-rev/antirev_overview.pdf"

with open(HTML_OUT, "w", encoding="utf-8") as f:
    f.write(html)
print(f"HTML written: {HTML_OUT}")

# ─────────────────────────────────────────────────────────────────────────────
# Convert to PDF via WeasyPrint
# ─────────────────────────────────────────────────────────────────────────────
print("Converting to PDF via WeasyPrint…")
doc = weasyprint.HTML(filename=HTML_OUT).write_pdf(
    PDF_OUT,
    presentational_hints=True,
)
print(f"PDF written:  {PDF_OUT}")
