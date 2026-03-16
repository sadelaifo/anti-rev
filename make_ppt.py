"""Generate antirev technical presentation."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
import copy

# ── Palette ──────────────────────────────────────────────────────────────────
BG        = RGBColor(0x0D, 0x1B, 0x2A)   # dark navy
ACCENT    = RGBColor(0x00, 0xB4, 0xD8)   # cyan
ACCENT2   = RGBColor(0xF7, 0x7F, 0x00)   # orange
WHITE     = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT     = RGBColor(0xCA, 0xD3, 0xDF)
GREEN     = RGBColor(0x06, 0xD6, 0xA0)
RED       = RGBColor(0xEF, 0x47, 0x6F)
GREY_BG   = RGBColor(0x1A, 0x2B, 0x3C)
CARD_BG   = RGBColor(0x12, 0x24, 0x35)

W = Inches(13.33)
H = Inches(7.5)

prs = Presentation()
prs.slide_width  = W
prs.slide_height = H

BLANK = prs.slide_layouts[6]  # truly blank


# ── Helpers ───────────────────────────────────────────────────────────────────

def add_slide():
    sl = prs.slides.add_slide(BLANK)
    bg = sl.background.fill
    bg.solid()
    bg.fore_color.rgb = BG
    return sl

def box(sl, x, y, w, h, fill=None, line=None, line_w=None):
    from pptx.util import Pt
    shape = sl.shapes.add_shape(1, x, y, w, h)   # MSO_SHAPE_TYPE.RECTANGLE=1
    shape.line.fill.background() if line is None else None
    if fill:
        shape.fill.solid()
        shape.fill.fore_color.rgb = fill
    else:
        shape.fill.background()
    if line:
        shape.line.color.rgb = line
        if line_w:
            shape.line.width = line_w
    else:
        shape.line.fill.background()
    return shape

def txt(sl, text, x, y, w, h, size=18, bold=False, color=WHITE,
        align=PP_ALIGN.LEFT, wrap=True, italic=False):
    tb = sl.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = wrap
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    run.font.italic = italic
    return tb

def header_bar(sl, title, subtitle=None):
    """Top accent bar + title."""
    box(sl, 0, 0, W, Inches(0.07), fill=ACCENT)
    txt(sl, title, Inches(0.45), Inches(0.18), Inches(10), Inches(0.65),
        size=28, bold=True, color=WHITE)
    if subtitle:
        txt(sl, subtitle, Inches(0.45), Inches(0.78), Inches(10), Inches(0.4),
            size=14, color=ACCENT, italic=True)

def bullet_block(sl, items, x, y, w, h, title=None, title_color=ACCENT,
                 item_size=14, title_size=15, gap=Inches(0.02)):
    """Render a titled bullet list inside a card."""
    box(sl, x, y, w, h, fill=CARD_BG, line=ACCENT, line_w=Pt(0.75))
    cy = y + Inches(0.15)
    if title:
        txt(sl, title, x + Inches(0.15), cy, w - Inches(0.3), Inches(0.35),
            size=title_size, bold=True, color=title_color)
        cy += Inches(0.38)
    for item in items:
        indent = 0
        label = item
        col = LIGHT
        if item.startswith("  "):
            indent = Inches(0.2)
            label = item.lstrip()
            col = RGBColor(0x90, 0xA8, 0xBB)
        if label.startswith("✓"):
            col = GREEN
        elif label.startswith("✗"):
            col = RED
        txt(sl, label, x + Inches(0.2) + indent, cy,
            w - Inches(0.4) - indent, Inches(0.32),
            size=item_size, color=col)
        cy += Inches(0.30)

def flow_arrow(sl, x1, y, x2, color=ACCENT):
    """Horizontal arrow from x1 to x2 at height y."""
    from pptx.util import Pt
    connector = sl.shapes.add_connector(1, x1, y, x2, y)  # straight
    connector.line.color.rgb = color
    connector.line.width = Pt(2)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 1 — Title
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
box(sl, 0, 0, W, Inches(0.12), fill=ACCENT)
box(sl, 0, Inches(7.38), W, Inches(0.12), fill=ACCENT)

# big title
txt(sl, "AntiRev", Inches(1), Inches(1.6), Inches(11), Inches(1.4),
    size=64, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
txt(sl, "ELF Binary Protection — Technical Overview",
    Inches(1), Inches(3.0), Inches(11), Inches(0.6),
    size=22, color=ACCENT, align=PP_ALIGN.CENTER)
txt(sl, "Encryption · In-Memory Execution · Dynamic Library Interception",
    Inches(1), Inches(3.7), Inches(11), Inches(0.5),
    size=15, color=LIGHT, align=PP_ALIGN.CENTER, italic=True)
txt(sl, "March 2026", Inches(1), Inches(5.5), Inches(11), Inches(0.4),
    size=13, color=LIGHT, align=PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 2 — Problem Statement
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Problem Statement", "What are we protecting against?")

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
bullet_block(sl, problems, Inches(0.35), Inches(1.3), Inches(6.0), Inches(3.5),
             title="Threats & Constraints", title_color=RED)
bullet_block(sl, goals,   Inches(6.85), Inches(1.3), Inches(6.1), Inches(3.5),
             title="Goals", title_color=GREEN)

txt(sl, "Requirement: protect compiled binaries with no modifications to source or build system",
    Inches(0.35), Inches(5.1), Inches(12.6), Inches(0.5),
    size=13, color=ACCENT, italic=True, align=PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 3 — Encryption Options
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Encryption Algorithm Options", "Comparing candidates for binary-file encryption")

COL_W = Inches(3.9)
COL_H = Inches(5.1)
Y0 = Inches(1.25)

# AES-256-GCM
aes_items = [
    "AES-256-GCM",
    "✓ AEAD — confidentiality + integrity",
    "✓ Hardware AES-NI on x86-64 & ARMv8",
    "✓ FIPS 140-2 compliant",
    "✓ Widely supported (OpenSSL, BoringSSL)",
    "✗ GCM nonce reuse is catastrophic",
    "✗ Slightly more complex API than CTR",
    "",
    "Verdict: chosen — best hw-accel + auth",
]
bullet_block(sl, aes_items, Inches(0.3), Y0, COL_W, COL_H,
             title="AES-256-GCM", title_color=GREEN)

# ChaCha20-Poly1305
cc_items = [
    "ChaCha20-Poly1305",
    "✓ AEAD — same security guarantees",
    "✓ Faster on CPUs without AES-NI",
    "✓ Immune to timing side-channels",
    "✓ TLS 1.3 standard cipher",
    "✗ Slower on modern x86 with AES-NI",
    "✗ Less common in embedded/RTOS libs",
    "",
    "Verdict: valid alternative for ARM cores\n  without crypto extensions",
]
bullet_block(sl, cc_items, Inches(4.72), Y0, COL_W, COL_H,
             title="ChaCha20-Poly1305", title_color=ACCENT)

# AES-256-CBC
cbc_items = [
    "AES-256-CBC",
    "✓ Universally supported",
    "✓ Simple implementation",
    "✗ No authentication — malleable",
    "✗ Requires separate HMAC layer",
    "✗ Padding oracle attacks possible",
    "✗ Does not detect tampering",
    "",
    "Verdict: rejected — no integrity check",
]
bullet_block(sl, cbc_items, Inches(9.13), Y0, COL_W, COL_H,
             title="AES-256-CBC", title_color=RED)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 4 — Decision
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Encryption Decision", "Why AES-256-GCM was selected")

# Decision box
box(sl, Inches(0.35), Inches(1.25), Inches(12.6), Inches(1.0),
    fill=RGBColor(0x00, 0x3A, 0x52), line=ACCENT, line_w=Pt(1.5))
txt(sl, "Selected: AES-256-GCM  |  Key size: 256-bit  |  IV: 96-bit random per file  |  Tag: 128-bit",
    Inches(0.5), Inches(1.35), Inches(12.2), Inches(0.7),
    size=17, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)

reasons = [
    "• AEAD cipher — a single primitive provides both confidentiality and tamper detection.",
    "  → If ciphertext is bit-flipped (tampering/corruption), GCM tag verification fails and the binary is rejected.",
    "• AES-NI hardware acceleration available on all modern x86-64 and ARMv8 cores.",
    "  → Decryption of a 10 MB ELF takes < 5 ms even on modest hardware.",
    "• Random 96-bit IV generated per file by protect.py — nonce reuse eliminated by design.",
    "• OpenSSL EVP API used — portable across Linux distributions, already available via Node.js bundled libs.",
    "• FIPS 140-2 compliance relevant for future enterprise/government deployments.",
    "• One key (256-bit) per protected binary — future upgrade path to per-machine keys from license server.",
]
bullet_block(sl, reasons, Inches(0.35), Inches(2.45), Inches(12.6), Inches(3.8),
             title="Rationale", item_size=13)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 5 — How Binary Encryption Works
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "How Binary Encryption Works", "Offline protect.py tool — build-time step")

# Left: offline flow
steps = [
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
bullet_block(sl, steps, Inches(0.35), Inches(1.25), Inches(5.8), Inches(4.8),
             title="protect.py — offline steps", item_size=13)

# Right: bundle format diagram
bx = Inches(6.6)
by = Inches(1.25)
bw = Inches(6.35)
box(sl, bx, by, bw, Inches(0.45), fill=RGBColor(0x00,0x4E,0x6E), line=ACCENT, line_w=Pt(1))
txt(sl, "BUNDLE FORMAT (appended to stub ELF)", bx+Inches(0.1), by+Inches(0.05), bw-Inches(0.2), Inches(0.35),
    size=13, bold=True, color=ACCENT)

rows = [
    ("num_files",            "4B LE",  GREY_BG),
    ("name_len + name",      "var",    CARD_BG),
    ("flags (bit0=is_main)", "1B",     GREY_BG),
    ("IV",                   "12B",    CARD_BG),
    ("GCM tag",              "16B",    GREY_BG),
    ("ciphertext size",      "8B LE",  CARD_BG),
    ("ciphertext",           "N bytes",GREY_BG),
    ("↑ repeated per file",  "",       BG),
    ("bundle_start_offset",  "8B LE",  RGBColor(0x1A,0x3A,0x1A)),
    ("AES-256 key",          "32B",    RGBColor(0x3A,0x1A,0x00)),
    ("magic ANTREV01",       "8B",     RGBColor(0x2A,0x00,0x2A)),
]
ry = by + Inches(0.48)
rh = Inches(0.36)
for label, size, fill_col in rows:
    box(sl, bx, ry, bw*0.72, rh, fill=fill_col,
        line=RGBColor(0x30,0x50,0x70), line_w=Pt(0.5))
    txt(sl, label, bx+Inches(0.08), ry+Inches(0.05), bw*0.72-Inches(0.1), rh-Inches(0.05),
        size=11, color=LIGHT)
    if size:
        box(sl, bx+bw*0.72, ry, bw*0.28, rh, fill=fill_col,
            line=RGBColor(0x30,0x50,0x70), line_w=Pt(0.5))
        txt(sl, size, bx+bw*0.72+Inches(0.05), ry+Inches(0.05),
            bw*0.28-Inches(0.05), rh-Inches(0.05),
            size=11, color=ACCENT2)
    ry += rh

txt(sl, "← 48-byte trailer", bx+bw+Inches(0.05), by+Inches(0.48)+rh*8+Inches(0.05),
    Inches(0.9), rh*3, size=10, color=ACCENT2)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 6 — Runtime Flow (stub)
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Runtime Flow", "How the stub decrypts and launches the protected binary")

steps_rt = [
    ("1", "Open /proc/self/exe", "Read last 48 bytes → verify ANTREV01 magic → extract bundle_start_offset and AES key"),
    ("2", "Read bundle",         "pread() full bundle into malloc'd RAM buffer"),
    ("3", "Decrypt files",       "For each entry: AES-256-GCM decrypt → verify GCM tag → abort if tampered"),
    ("4", "Write to memfds",     "memfd_create() per file → write plaintext → seek back to 0. File never touches disk."),
    ("5", "Wipe secrets",        "explicit_bzero(key) + explicit_bzero(bundle buffer) — key gone from RAM"),
    ("6", "Build LD_PRELOAD",    "Write dlopen_shim.so (embedded blob) to its own memfd → set LD_PRELOAD=/proc/self/fd/N"),
    ("7", "Build env map",       "ANTIREV_FD_MAP=libfoo.so=<fd>,libbar.so=<fd>,..."),
    ("8", "fexecve(main_fd,...)", "Replace process image in-place — same PID, no fork, no disk. Done."),
]

sx = Inches(0.35)
sy = Inches(1.3)
num_w  = Inches(0.45)
hd_w   = Inches(2.8)
desc_w = Inches(9.6)
row_h  = Inches(0.57)

for num, head, desc in steps_rt:
    # number circle
    box(sl, sx, sy+Inches(0.05), num_w, row_h-Inches(0.1), fill=ACCENT, line=None)
    txt(sl, num, sx, sy+Inches(0.1), num_w, row_h-Inches(0.1),
        size=16, bold=True, color=BG, align=PP_ALIGN.CENTER)
    # heading
    box(sl, sx+num_w, sy, hd_w, row_h, fill=GREY_BG, line=RGBColor(0x20,0x40,0x60), line_w=Pt(0.5))
    txt(sl, head, sx+num_w+Inches(0.1), sy+Inches(0.1), hd_w-Inches(0.2), row_h-Inches(0.1),
        size=12, bold=True, color=ACCENT2)
    # description
    box(sl, sx+num_w+hd_w, sy, desc_w, row_h, fill=CARD_BG, line=RGBColor(0x20,0x40,0x60), line_w=Pt(0.5))
    txt(sl, desc, sx+num_w+hd_w+Inches(0.1), sy+Inches(0.08), desc_w-Inches(0.2), row_h-Inches(0.1),
        size=11, color=LIGHT)
    sy += row_h


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 7 — dlopen / .so Interception
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Handling dlopen & Encrypted .so Files", "How custom shared libraries are intercepted at runtime")

# Problem
bullet_block(sl,
    ["• Target binary calls dlopen(\"libfoo.so\") at runtime",
     "• Standard dlopen searches filesystem — encrypted file on disk is useless",
     "• We cannot modify the target binary's source",
     "• Solution: intercept dlopen() via LD_PRELOAD before it hits the filesystem"],
    Inches(0.35), Inches(1.25), Inches(12.6), Inches(1.85),
    title="The Problem", title_color=RED, item_size=13)

# Three column: shim / env / flow
shim = [
    "• Small C shared library compiled for each target arch",
    "• Embedded as byte array in stub (dlopen_shim_blob.h)",
    "• Wraps dlopen() symbol — runs before libc's version",
    "• At startup: parses ANTIREV_FD_MAP env var into hash map",
    "• On each dlopen(name) call:",
    "  → If name in map: open /proc/self/fd/<N> instead",
    "  → Otherwise: forward to real dlopen unchanged",
]
bullet_block(sl, shim, Inches(0.35), Inches(3.3), Inches(5.8), Inches(3.5),
             title="dlopen_shim.so", title_color=ACCENT, item_size=12)

env_items = [
    "Set by stub before fexecve():",
    "",
    "LD_PRELOAD=",
    "  /proc/self/fd/<shim_fd>",
    "",
    "ANTIREV_FD_MAP=",
    "  libfoo.so=<fd_A>,",
    "  libbar.so=<fd_B>",
    "",
    "• shim memfd never appears in /proc/pid/maps by filename",
    "• .so memfds are anonymous — not visible as files",
]
bullet_block(sl, env_items, Inches(6.5), Inches(3.3), Inches(3.0), Inches(3.5),
             title="Environment Variables", title_color=ACCENT2, item_size=11)

result_items = [
    "✓ dlopen() works transparently",
    "✓ No disk files for any .so",
    "✓ Zero source changes to target",
    "✓ Unknown .so names pass through",
    "✓ Works with multiple .so files",
    "✓ Shim itself lives in a memfd",
]
bullet_block(sl, result_items, Inches(9.85), Inches(3.3), Inches(3.1), Inches(3.5),
             title="Result", title_color=GREEN, item_size=12)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 8 — Architecture Diagram
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Code Architecture", "Three-component design")

# ── Row 1: three components ──────────────────────────────────────
comp_y = Inches(1.3)
comp_h = Inches(2.2)
comp_w = Inches(3.9)

# protect.py
box(sl, Inches(0.3),  comp_y, comp_w, comp_h, fill=CARD_BG, line=ACCENT2, line_w=Pt(1.5))
txt(sl, "protect.py", Inches(0.4), comp_y+Inches(0.1), comp_w-Inches(0.2), Inches(0.4),
    size=15, bold=True, color=ACCENT2)
txt(sl, "encryptor/protect.py\n\n"
        "• Reads stub ELF binary\n"
        "• Encrypts main ELF + .so files\n"
        "• Serialises bundle format\n"
        "• Appends bundle + trailer to stub\n"
        "• Outputs protected binary",
    Inches(0.4), comp_y+Inches(0.5), comp_w-Inches(0.2), Inches(1.6),
    size=11, color=LIGHT)

# stub
box(sl, Inches(4.72), comp_y, comp_w, comp_h, fill=CARD_BG, line=ACCENT, line_w=Pt(1.5))
txt(sl, "stub  (launcher)", Inches(4.82), comp_y+Inches(0.1), comp_w-Inches(0.2), Inches(0.4),
    size=15, bold=True, color=ACCENT)
txt(sl, "stub/stub.c + stub/crypto.c\n\n"
        "• Entry point of protected binary\n"
        "• Reads + decrypts bundle from self\n"
        "• Creates memfds, writes plaintext\n"
        "• Wipes key from RAM\n"
        "• fexecve() — replaces self",
    Inches(4.82), comp_y+Inches(0.5), comp_w-Inches(0.2), Inches(1.6),
    size=11, color=LIGHT)

# dlopen_shim
box(sl, Inches(9.13), comp_y, comp_w, comp_h, fill=CARD_BG, line=GREEN, line_w=Pt(1.5))
txt(sl, "dlopen_shim.so", Inches(9.23), comp_y+Inches(0.1), comp_w-Inches(0.2), Inches(0.4),
    size=15, bold=True, color=GREEN)
txt(sl, "stub/dlopen_shim.c\n\n"
        "• Compiled per-arch → .so\n"
        "• Converted to C byte-array header\n"
        "• Embedded inside stub binary\n"
        "• LD_PRELOAD'd into target process\n"
        "• Intercepts dlopen() at runtime",
    Inches(9.23), comp_y+Inches(0.5), comp_w-Inches(0.2), Inches(1.6),
    size=11, color=LIGHT)

# arrows between components
arrow_y = comp_y + comp_h/2
# protect.py → stub (build time)
box(sl, Inches(4.2), arrow_y-Inches(0.18), Inches(0.52), Inches(0.36),
    fill=CARD_BG, line=None)
txt(sl, "appends\nbundle", Inches(4.2), arrow_y-Inches(0.25), Inches(0.52), Inches(0.4),
    size=9, color=ACCENT2, align=PP_ALIGN.CENTER)

# dlopen_shim → stub (embedded)
box(sl, Inches(8.63), arrow_y-Inches(0.18), Inches(0.5), Inches(0.36),
    fill=CARD_BG, line=None)
txt(sl, "embedded\nas blob", Inches(8.62), arrow_y-Inches(0.25), Inches(0.52), Inches(0.4),
    size=9, color=GREEN, align=PP_ALIGN.CENTER)

# ── Row 2: build system + tests ──────────────────────────────────
by2 = comp_y + comp_h + Inches(0.5)
box(sl, Inches(0.3), by2, Inches(5.7), Inches(1.9), fill=CARD_BG,
    line=RGBColor(0x50,0x50,0x80), line_w=Pt(1))
txt(sl, "CMakeLists.txt  +  cmake/*.py/cmake",
    Inches(0.4), by2+Inches(0.1), Inches(5.5), Inches(0.35),
    size=13, bold=True, color=LIGHT)
txt(sl, "• Builds stub (x86-64) and stub_aarch64 (ARM64, static)\n"
        "• Cross-compiles dlopen_shim.so for both arches via bin2h.py → header\n"
        "• Test targets: run_test, test_dlopen, test_multi_so, test_wrong_key, test_tamper, run_tests",
    Inches(0.4), by2+Inches(0.48), Inches(5.5), Inches(1.3),
    size=11, color=LIGHT)

box(sl, Inches(6.35), by2, Inches(6.65), Inches(1.9), fill=CARD_BG,
    line=RGBColor(0x50,0x50,0x80), line_w=Pt(1))
txt(sl, "tests/",
    Inches(6.45), by2+Inches(0.1), Inches(6.4), Inches(0.35),
    size=13, bold=True, color=LIGHT)
txt(sl, "tests/hello/          — simple ELF (prints hello + args)\n"
        "tests/dlopen/         — binary + mylib.so (tests shim)\n"
        "tests/multi_so/       — binary + libmath.so + libstr.so\n"
        "Negative tests: wrong key → GCM fail; bit-flip → tag fail",
    Inches(6.45), by2+Inches(0.48), Inches(6.4), Inches(1.3),
    size=11, color=LIGHT)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 9 — How to Use
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "How to Use AntiRev", "Step-by-step: protecting your NT executable")

use_steps = [
    ("Build the toolchain",
     "cmake -B build && cmake --build build",
     "Builds stub (x86-64 + ARM64) and all test binaries."),
    ("Generate / obtain key",
     "python3 encryptor/protect.py --gen-key mykey.bin",
     "Outputs a 32-byte (256-bit) random key. Keep this file secure."),
    ("Protect main binary (no .so files)",
     "python3 encryptor/protect.py \\\n"
     "  --stub   build/stub \\\n"
     "  --key    mykey.bin \\\n"
     "  --main   /path/to/your_app \\\n"
     "  --output your_app_protected",
     "Encrypts your_app, appends bundle to stub → outputs your_app_protected."),
    ("Protect binary with custom .so libraries",
     "python3 encryptor/protect.py \\\n"
     "  --stub   build/stub \\\n"
     "  --key    mykey.bin \\\n"
     "  --main   /path/to/your_app \\\n"
     "  --so     libfoo.so libbar.so \\\n"
     "  --output your_app_protected",
     "All listed .so files are also encrypted into the bundle. dlopen shim handles redirection."),
    ("Run protected binary",
     "./your_app_protected [original args...]",
     "Stub decrypts, memfds, wipes key, fexecve()s. Behaviour identical to unprotected binary."),
    ("Verify protection",
     "objdump -d your_app_protected   # shows only stub code\n"
     "strings  your_app_protected     # no readable strings from your_app",
     "Static analysis tools see only the small stub — your logic is not recoverable."),
]

sy = Inches(1.25)
num_w  = Inches(0.45)
hd_w   = Inches(2.7)
cmd_w  = Inches(4.8)
desc_w = Inches(4.7)
rh     = Inches(0.82)

for head, cmd, desc in use_steps:
    box(sl, Inches(0.3), sy, hd_w, rh, fill=GREY_BG,
        line=RGBColor(0x20,0x40,0x60), line_w=Pt(0.5))
    txt(sl, head, Inches(0.4), sy+Inches(0.08), hd_w-Inches(0.15), rh-Inches(0.1),
        size=12, bold=True, color=ACCENT2)
    box(sl, Inches(0.3)+hd_w, sy, cmd_w, rh, fill=RGBColor(0x05,0x10,0x1A),
        line=RGBColor(0x20,0x40,0x60), line_w=Pt(0.5))
    txt(sl, cmd, Inches(0.45)+hd_w, sy+Inches(0.08), cmd_w-Inches(0.2), rh-Inches(0.1),
        size=10, color=GREEN, italic=True)
    box(sl, Inches(0.3)+hd_w+cmd_w, sy, desc_w, rh, fill=CARD_BG,
        line=RGBColor(0x20,0x40,0x60), line_w=Pt(0.5))
    txt(sl, desc, Inches(0.45)+hd_w+cmd_w, sy+Inches(0.08), desc_w-Inches(0.2), rh-Inches(0.1),
        size=11, color=LIGHT)
    sy += rh

txt(sl, "Note: ANTIREV_KEY env var can override the embedded key (for testing without re-encrypting)",
    Inches(0.3), sy+Inches(0.05), Inches(12.7), Inches(0.35),
    size=11, color=ACCENT, italic=True)


# ═══════════════════════════════════════════════════════════════════════════
# SLIDE 10 — Status & Roadmap
# ═══════════════════════════════════════════════════════════════════════════
sl = add_slide()
header_bar(sl, "Current Status & Roadmap")

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
bullet_block(sl, done, Inches(0.35), Inches(1.25), Inches(6.1), Inches(3.8),
             title="Done", title_color=GREEN)
bullet_block(sl, todo, Inches(6.85), Inches(1.25), Inches(6.1), Inches(3.8),
             title="TODO / Roadmap", title_color=ACCENT2)

box(sl, Inches(0.35), Inches(5.25), Inches(12.6), Inches(0.9),
    fill=RGBColor(0x00,0x3A,0x52), line=ACCENT, line_w=Pt(1))
txt(sl, "All six test targets pass on x86-64. ARM64 tests pass via QEMU binfmt transparent emulation.",
    Inches(0.5), Inches(5.35), Inches(12.2), Inches(0.65),
    size=14, color=ACCENT, align=PP_ALIGN.CENTER)

# ── Save ──────────────────────────────────────────────────────────────────
out = "/home/yz/Documents/anti-rev/antirev_overview.pptx"
prs.save(out)
print(f"Saved: {out}")
