#!/usr/bin/env python3
"""Generate the 'kmod2 vs. current (memfd+daemon)' management report deck.

Audience: project manager — focus on security (where the key lives), the
release/CI pipeline, and the client upgrade process. Implementation detail is
kept to what is needed to reason about those.
"""
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# ── Palette ─────────────────────────────────────────────────────────
BG_DARK = RGBColor(0x1B, 0x1B, 0x2F)
BG_CARD = RGBColor(0x25, 0x25, 0x3D)
ACCENT  = RGBColor(0x00, 0xB4, 0xD8)
ACCENT2 = RGBColor(0x90, 0xE0, 0xEF)
ORANGE  = RGBColor(0xFF, 0xA6, 0x2B)
GREEN   = RGBColor(0x06, 0xD6, 0xA0)
RED     = RGBColor(0xEF, 0x47, 0x6F)
WHITE   = RGBColor(0xFF, 0xFF, 0xFF)
GRAY    = RGBColor(0xA0, 0xA0, 0xB0)
LIGHT   = RGBColor(0xE0, 0xE0, 0xE8)


def set_slide_bg(slide, color):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_textbox(slide, left, top, width, height):
    return slide.shapes.add_textbox(left, top, width, height)


def set_text(tf, text, size=18, color=WHITE, bold=False, alignment=PP_ALIGN.LEFT):
    tf.clear()
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.alignment = alignment
    return p


def add_para(tf, text, size=16, color=LIGHT, bold=False, space_before=Pt(4),
             space_after=Pt(2), level=0, alignment=PP_ALIGN.LEFT):
    p = tf.add_paragraph()
    p.text = text
    p.font.size = Pt(size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.space_before = space_before
    p.space_after = space_after
    p.level = level
    p.alignment = alignment
    return p


def add_bullet(tf, text, size=15, color=LIGHT, level=0):
    return add_para(tf, text, size=size, color=color, level=level,
                    space_before=Pt(3), space_after=Pt(1))


def add_rounded_rect(slide, left, top, width, height, fill_color=BG_CARD,
                     border_color=None):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1.5)
    else:
        shape.line.fill.background()
    return shape


def title_slide(prs, title, subtitle):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide, BG_DARK)
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.5), Inches(2.7), Inches(2), Pt(4))
    shape.fill.solid(); shape.fill.fore_color.rgb = ACCENT; shape.line.fill.background()
    tb = add_textbox(slide, Inches(1.5), Inches(1.0), Inches(7.2), Inches(1.6))
    set_text(tb.text_frame, title, size=38, color=WHITE, bold=True)
    tb = add_textbox(slide, Inches(1.5), Inches(2.9), Inches(7.5), Inches(2.0))
    set_text(tb.text_frame, subtitle, size=18, color=GRAY)
    return slide


def section_slide(prs, number, title, subtitle=""):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide, BG_DARK)
    tb = add_textbox(slide, Inches(0.8), Inches(1.0), Inches(1.5), Inches(2))
    set_text(tb.text_frame, "%02d" % number, size=72, color=ACCENT, bold=True)
    tb = add_textbox(slide, Inches(2.5), Inches(1.5), Inches(6.8), Inches(1.2))
    set_text(tb.text_frame, title, size=34, color=WHITE, bold=True)
    if subtitle:
        tb = add_textbox(slide, Inches(2.5), Inches(2.6), Inches(6.8), Inches(1.4))
        set_text(tb.text_frame, subtitle, size=17, color=GRAY)
    return slide


def content_slide(prs, title, bullets, subbullets=None, body_size=15):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide, BG_DARK)
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(10), Inches(0.9))
    shape.fill.solid(); shape.fill.fore_color.rgb = BG_CARD; shape.line.fill.background()
    tb = add_textbox(slide, Inches(0.6), Inches(0.12), Inches(8.9), Inches(0.7))
    set_text(tb.text_frame, title, size=24, color=ACCENT, bold=True)
    tb = add_textbox(slide, Inches(0.6), Inches(1.05), Inches(8.9), Inches(6.2))
    tf = tb.text_frame; tf.word_wrap = True
    first = True
    for i, b in enumerate(bullets):
        color = LIGHT
        if b.startswith("##"):
            b = b[2:].strip(); color = ORANGE
        if first:
            set_text(tf, b, size=body_size, color=color, bold=(color == ORANGE)); first = False
        else:
            add_bullet(tf, b, size=body_size, color=color, level=0)
            if color == ORANGE:
                tf.paragraphs[-1].font.bold = True
        if subbullets and i in subbullets:
            for sb in subbullets[i]:
                add_bullet(tf, sb, size=body_size - 2, color=GRAY, level=1)
    return slide


def two_col_slide(prs, title, left_title, left_bullets, right_title, right_bullets,
                  left_color=ACCENT, right_color=GREEN, body_size=13):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    set_slide_bg(slide, BG_DARK)
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(10), Inches(0.9))
    shape.fill.solid(); shape.fill.fore_color.rgb = BG_CARD; shape.line.fill.background()
    tb = add_textbox(slide, Inches(0.6), Inches(0.12), Inches(8.9), Inches(0.7))
    set_text(tb.text_frame, title, size=24, color=ACCENT, bold=True)

    add_rounded_rect(slide, Inches(0.4), Inches(1.05), Inches(4.5), Inches(6.1), border_color=left_color)
    tb = add_textbox(slide, Inches(0.6), Inches(1.15), Inches(4.2), Inches(0.5))
    set_text(tb.text_frame, left_title, size=16, color=left_color, bold=True)
    tb = add_textbox(slide, Inches(0.6), Inches(1.65), Inches(4.2), Inches(5.4))
    tf = tb.text_frame; tf.word_wrap = True
    for i, b in enumerate(left_bullets):
        (set_text if i == 0 else add_bullet)(tf, b, size=body_size, color=LIGHT)

    add_rounded_rect(slide, Inches(5.1), Inches(1.05), Inches(4.5), Inches(6.1), border_color=right_color)
    tb = add_textbox(slide, Inches(5.3), Inches(1.15), Inches(4.2), Inches(0.5))
    set_text(tb.text_frame, right_title, size=16, color=right_color, bold=True)
    tb = add_textbox(slide, Inches(5.3), Inches(1.65), Inches(4.2), Inches(5.4))
    tf = tb.text_frame; tf.word_wrap = True
    for i, b in enumerate(right_bullets):
        (set_text if i == 0 else add_bullet)(tf, b, size=body_size, color=LIGHT)
    return slide


# ═══════════════════════════════════════════════════════════════════════
prs = Presentation()
prs.slide_width = Inches(10)
prs.slide_height = Inches(7.5)

# ── 1. Title ────────────────────────────────────────────────────────
title_slide(prs,
    "Binary Protection: Two Architectures",
    "Current production design  (memfd + daemon + LD_PRELOAD shims)\n"
    "vs.  kmod2  (antirevfs decrypting kernel filesystem)\n\n"
    "Design · CI build output · Runtime footprint · Upgrade process · Key & security posture\n"
    "Prepared for project review — 2026")

# ── 2. Executive summary ────────────────────────────────────────────
content_slide(prs, "Executive Summary (TL;DR)", [
    "##Both designs solve the same problem",
    "Ship 100+ exes / 550+ libs / 1000+ Python scripts to customer-owned hardware so the binaries cannot be reverse-engineered. Plaintext only ever exists in RAM; ciphertext on disk.",
    "",
    "##The two approaches differ in WHERE protection lives",
    "Current: a userspace launcher + a decrypt daemon + injected LD_PRELOAD shims. Each binary is re-wrapped.",
    "kmod2: a kernel filesystem that decrypts files on read. Binaries are untouched; a mount point hides them.",
    "",
    "##The key-position difference is the headline for security",
    "Current: AES key is embedded ONLY inside the launcher/daemon binaries; the 550 lib files on disk are keyless ciphertext — useless if copied.",
    "kmod2: AES key is embedded in EVERY encrypted file. A raw copy of the disk tree is decryptable — protection then rests on the mount + access gate + namespace isolation.",
    "",
    "##Status",
    "Current design = shipping production path. kmod2 = working proof-of-concept / candidate, validated on the real x86-64 and SLES targets, not yet the release path.",
], body_size=14)

# ════════════════ SECTION 1: DESIGN ════════════════
section_slide(prs, 1, "Design",
              "How each architecture protects the binaries")

# Current design
content_slide(prs, "Current design — memfd + daemon + shims", [
    "##Concept: decrypt into anonymous RAM files, run from there",
    "Every protected executable is wrapped in a small C 'stub' launcher. At start it decrypts the real program into a memfd (a kernel in-memory file with no disk path) and runs it via fexecve. No plaintext ever touches the disk.",
    "",
    "##A shared daemon decrypts the 550 libraries once",
    "'lrxd' scans the install tree, decrypts every encrypted .so into memory once, and hands the in-memory file descriptors to each app process over a local socket. 100 processes share one decrypt instead of 55,000 copies.",
    "",
    "##LD_PRELOAD shims keep the app working transparently",
    "Injected helper libraries hide the in-memory identity (so /proc/self/exe still looks normal), redirect dlopen() of encrypted libs, and preserve the normal library-load order.",
    "",
    "##Where the key lives",
    "Embedded in the launcher and daemon binaries only. The library files on disk are keyless ciphertext.",
], body_size=14)

# kmod2 design
content_slide(prs, "kmod2 design — antirevfs kernel filesystem", [
    "##Concept: a filesystem that decrypts on read",
    "Ciphertext lives in a hidden lower tree (.enc/). A small kernel module, antirevfs, is mounted ON TOP of it at the real install path. When any program reads a file, the kernel decrypts it on the fly in the page cache. The app, glibc and Python see plaintext at the real paths — no launcher, no shims, no daemon.",
    "",
    "##Far simpler integration",
    "Business binaries are NOT modified or re-wrapped. Native symbol resolution 'just works', which removes a whole class of dependency-ordering problems the shim design must work around.",
    "",
    "##A kernel access-gate decides who may decrypt",
    "Only authorized processes (an allow-list / signature check) get plaintext through the mount. Copy tools (cp, file managers, backup) are served the ciphertext with the key stripped — so a copy yields useless bytes.",
    "",
    "##Where the key lives",
    "Embedded in every encrypted file. No mount password, no keyring. Convenience cost: the raw .enc/ tree is decryptable if copied (see security section).",
], body_size=13)

# Side by side
two_col_slide(prs, "Design comparison at a glance",
    "Current  (memfd + daemon)",
    [
        "Userspace only — no kernel changes",
        "Each binary re-wrapped as a stub launcher",
        "Decrypt daemon process runs alongside app",
        "LD_PRELOAD shims injected into every process",
        "Plaintext lives in RAM-only memfds",
        "/proc shows memfd:<random> instead of real path",
        "",
        "Must work around: symbol order, dlopen,",
        "  protobuf dedup, implicit inter-lib deps",
        "",
        "KEY: only inside launcher + daemon binaries",
        "LIBS ON DISK: keyless ciphertext (safe to copy)",
        "",
        "Status: SHIPPING / production",
    ],
    "kmod2  (antirevfs)",
    [
        "Requires a signed kernel module on the box",
        "Binaries untouched — mounted, not wrapped",
        "No daemon — kernel page cache shares plaintext",
        "No LD_PRELOAD — native loading, real paths",
        "Plaintext lives in kernel page cache (RAM)",
        "/proc shows real paths — no memfd artifact",
        "",
        "Dependency problems largely DISAPPEAR",
        "  (native ld.so resolution)",
        "",
        "KEY: embedded in every file",
        "DISK TREE: decryptable if copied (needs gate +",
        "  namespace isolation to stay protected)",
        "",
        "Status: working PoC / candidate",
    ], body_size=12)

# Key position — security-focused slide for the PM
content_slide(prs, "Where is the AES key? (the security headline)", [
    "##Current design — key is concentrated in executables",
    "The 32-byte AES-256 key is appended inside the launcher of each protected exe and inside the daemon binary. The 550 library files are encrypted WITHOUT the key (keyless container).",
    "A customer copying the lib folder to a USB stick gets keyless ciphertext — undecryptable. The key only travels inside the program binaries themselves.",
    "",
    "##kmod2 — key is embedded in every file",
    "Each encrypted file carries its own key in a trailer; the kernel reads it at decrypt time. There is no separate key file, no password, no keyring to manage.",
    "Trade-off: a raw copy of the .enc/ tree IS decryptable. Protection then depends on (1) the mount stripping the key for unauthorized readers, (2) the access gate, and (3) keeping the .enc/ tree in an isolated mount namespace the operator cannot browse.",
    "",
    "##Both share one hard limit",
    "The CPU runs plaintext, so plaintext is in RAM. Anyone with root on the LIVE box can read it. Our threat model says that's out of scope: the at-box operator is non-technical, and the capable competitor only ever receives copied bits, never the running box.",
    "",
    "##Recommended backstop for both: factory TPM-seal the key per unit",
    "Sealed key never leaves the box and won't unseal on different hardware — exfiltrated ciphertext becomes doubly useless.",
], body_size=13)

# ════════════════ SECTION 2: CI BUILD OUTPUT ════════════════
section_slide(prs, 2, "After the CI build",
              "What the software package contains — new files & modified files")

content_slide(prs, "Release pipeline — two stages (both designs)", [
    "##Stage A — Compile (CI, key-independent, reusable)",
    "Builds the protection toolchain from source. Produces architecture binaries with NO customer key in them. The same Stage-A output is reused across all deployments.",
    "  Current: stub launcher, antirev_shim_<arch>.so, lrxd-<arch> daemon, packer tools",
    "  kmod2: antirevfs.ko (one per kernel version, via DKMS), mount tools",
    "",
    "##Stage B — Pack (per-deployment, uses the secret key)",
    "Takes the business install tree + the deployment key + Stage-A artifacts and produces the encrypted, shippable package. This is the step that injects/uses the key and yields the client deliverable.",
    "  Current: antirev-pack.py  → re-wrapped exes + encrypted libs + daemon",
    "  kmod2: antirev-fs-pack.py → ciphertext .enc/ lower tree + manifest",
    "",
    "##Why this split matters to release management",
    "Stage A is ordinary CI (build once, sign, archive). Stage B is the controlled, key-bearing step that should run in a protected release environment. The key is the only secret; everything else is reproducible from source.",
], body_size=14)

two_col_slide(prs, "After CI: what the package looks like",
    "Current  (memfd + daemon)",
    [
        "NEW files added to the tree:",
        "  • lrxd-x86_64 / lrxd-aarch64  (decrypt daemon)",
        "  • antirev_shim_<arch>.so  (one per arch)",
        "  • launch/start scripts that set LD_PRELOAD",
        "",
        "MODIFIED (replaced in place):",
        "  • every protected .exe → stub launcher +",
        "    embedded ciphertext + key trailer",
        "  • every encrypted .so → keyless ciphertext",
        "  • Python that loads encrypted .so → uses",
        "    antirev_client",
        "",
        "KEPT SEPARATE / SECRET:",
        "  • the 64-hex-char key file (0600), or the",
        "    TPM-sealed key on the unit",
        "",
        "3rd-party libs (libprotobuf, Boost…): untouched",
    ],
    "kmod2  (antirevfs)",
    [
        "NEW files added:",
        "  • antirevfs.ko  (signed kernel module)",
        "  • mount tools: antirev-mount,",
        "    antirev-mount-rw, antirev-remount-proj.sh",
        "  • .enc/ ciphertext lower tree (mirrors bin/lib)",
        "  • antirev-fs-manifest.json  (what was encrypted)",
        "  • /etc/authorized_apps.txt  (gate allow-list)",
        "  • boot wrapper / systemd unit to mount it",
        "",
        "MODIFIED:",
        "  • business binaries are NOT modified —",
        "    the original install path becomes a MOUNT",
        "    POINT over the .enc/ tree",
        "",
        "KEY: embedded inside each .enc/ file",
        "  (no separate key file to ship)",
        "",
        "3rd-party / preloaded libs: left plaintext in tree",
    ], body_size=12)

# ════════════════ SECTION 3: RUNTIME ════════════════
section_slide(prs, 3, "At runtime",
              "What the install directory and the running processes look like")

two_col_slide(prs, "Runtime footprint on the box",
    "Current  (memfd + daemon)",
    [
        "ON DISK (install dir):",
        "  • stub-wrapped exes + keyless encrypted .so",
        "  • lrxd daemon binary",
        "  → looks like normal files; contents ciphertext",
        "",
        "RUNNING PROCESSES:",
        "  • one extra long-lived process: lrxd daemon",
        "  • each app process carries LD_PRELOAD shims",
        "",
        "PROCESS / FS ARTIFACTS (observable):",
        "  • /proc/<pid>/exe → memfd:<random> (deleted)",
        "  • /proc/<pid>/maps → memfd entries, no real",
        "    library paths",
        "  • abstract Unix socket (daemon)",
        "  • /tmp/antirev_<pid>_XXXX symlink dirs",
        "  • each lib held open as a memory fd",
    ],
    "kmod2  (antirevfs)",
    [
        "ON DISK:",
        "  • .enc/ ciphertext lower tree (hidden)",
        "  • install path = a MOUNT POINT showing",
        "    decrypted files at real paths",
        "",
        "RUNNING PROCESSES:",
        "  • NO extra daemon process",
        "  • apps run unmodified, no injected libs",
        "",
        "KERNEL / FS ARTIFACTS:",
        "  • lsmod shows 'antirevfs' module loaded",
        "  • mount list shows antirevfs (+ overlay for",
        "    writable bin/lib)",
        "  • /proc/<pid>/maps → REAL paths (no memfd)",
        "  • page cache shared across processes for free",
        "  • kernel gate enforces who may decrypt",
    ], body_size=12)

content_slide(prs, "Runtime: the writable-view detail (kmod2)", [
    "##The mount is read-only by design",
    "antirevfs only serves shipped, encrypted content. But real business software writes lock / pid / log files right next to its binaries (e.g. the GUI writes QtApplication.pid into bin/).",
    "",
    "##Fix: a stock overlay provides a writable top layer",
    "antirev-mount-rw stacks a normal writable layer over the decrypting filesystem. Decrypted library reads fall through to antirevfs; the app's runtime writes land in the writable upper and NEVER touch the ciphertext .enc/ tree. Both bin/ and lib/ are mounted this way in the reference deployment.",
    "",
    "##Net operator-visible picture",
    "A normal-looking bin/ and lib/ that the app reads and writes as usual — while the real bytes on disk stay encrypted, and only authorized processes can pull plaintext through the mount.",
], body_size=14)

# ════════════════ SECTION 4: PARTIAL UPGRADE ════════════════
section_slide(prs, 4, "Partial upgrade",
              "Replacing / adding only some libraries in the field")

two_col_slide(prs, "Partial upgrade — what changes & what the technician does",
    "Current  (memfd + daemon)",
    [
        "MUST reuse the SAME deployment key.",
        "All libs + exes + daemon share ONE key, and the",
        "daemon's socket identity is derived from it.",
        "",
        "Technician steps:",
        "  1. Re-encrypt the changed/new .so with the",
        "     existing key (antirev-pack / encrypt-lib)",
        "  2. Drop the new ciphertext libs into the tree",
        "  3. If a NEW dependency edge was added, re-pack",
        "     the affected exe (needed-libs list changes)",
        "  4. Restart the lrxd daemon so it re-scans &",
        "     re-decrypts the new libs",
        "",
        "Key preservation:",
        "  • Keep the original key file (or unseal from",
        "    TPM). A wrong/new key breaks the whole set.",
    ],
    "kmod2  (antirevfs)",
    [
        "Each file carries its OWN key, so a new lib does",
        "NOT have to match a global key — but in practice",
        "use the same project keyfile for consistency.",
        "",
        "Technician steps:",
        "  1. Re-encrypt the changed/new ELF into .enc/",
        "     (antirev-fs-pack, embedded-key form)",
        "  2. Swap the file(s) in the .enc/ lower tree",
        "  3. REMOUNT that tree — antirevfs caches the",
        "     encrypted-vs-plaintext decision per file at",
        "     first lookup; without a remount the stale",
        "     classification persists and reads fail",
        "",
        "Key preservation:",
        "  • Keep proj.key.hex to add matching files;",
        "    the existing files already embed their keys",
        "  • No daemon to restart",
    ], body_size=12)

content_slide(prs, "Partial upgrade — key takeaways for release planning", [
    "##The key is the one artifact that MUST survive every upgrade",
    "Current design: mandatory — every file in the deployment is bound to one key; new libs must be encrypted with it or the daemon can't serve a consistent set.",
    "kmod2: less strict — files self-describe their key — but keeping one project keyfile keeps the manifest and tooling clean.",
    "",
    "##Practical guidance",
    "Store the per-deployment key in the release vault AND TPM-seal a copy on each unit at the factory. Partial patches then never need to ship a key — the technician re-encrypts against the retained key and drops files in.",
    "",
    "##The one operational gotcha per design",
    "Current: remember to RESTART the daemon (it decrypts at startup).",
    "kmod2: remember to REMOUNT (inode classification is cached); a quiet stack is needed because mapped libraries pin the module.",
], body_size=14)

# ════════════════ SECTION 5: FULL UPGRADE ════════════════
section_slide(prs, 5, "Full upgrade",
              "Replacing the entire protected software set")

two_col_slide(prs, "Full upgrade — technician process",
    "Current  (memfd + daemon)",
    [
        "1. Stop the business stack and the lrxd daemon",
        "2. Decide on key:",
        "   • keep existing key → drop-in replacement",
        "   • rotate key → everything re-packed together",
        "     (exes + libs + daemon) so they stay",
        "     consistent; re-seal the new key in TPM",
        "3. Deploy the new packed tree (exes, libs,",
        "   daemon, shims, scripts) in one shot",
        "4. Start daemon, then the stack",
        "",
        "No kernel dependency — pure userspace swap.",
        "",
        "Rollback: keep the previous packed tree +",
        "its key; swap back and restart.",
    ],
    "kmod2  (antirevfs)",
    [
        "1. Stop the business stack (mapped .so pin the",
        "   module; the stack must be quiet to unmount)",
        "2. Tear down the mounts (antirev-mount-rw --down)",
        "3. Replace the .enc/ lower tree with the new",
        "   packed tree (+ new manifest)",
        "4. If the kernel changed: DKMS rebuilds /",
        "   re-signs antirevfs.ko for the new kernel",
        "5. Re-mount (antirev-remount-proj.sh automates",
        "   umount→rmmod→insmod→mount), start the stack",
        "",
        "Extra dependency: the signed kernel module must",
        "match the running kernel (Secure Boot signing).",
        "",
        "Rollback: keep the previous .enc/ tree; remount.",
    ], body_size=12)

content_slide(prs, "Full upgrade — what release management must own", [
    "##Current design — fully self-contained, no host coupling",
    "A full upgrade is a userspace file swap plus a daemon restart. Nothing depends on the customer's kernel. Simplest to support across heterogeneous customer hardware.",
    "",
    "##kmod2 — adds a kernel-module lifecycle to own",
    "The .ko must be built and signed for each customer kernel version. DKMS rebuilds it automatically on kernel upgrade, but Secure Boot requires our module-signing key to be enrolled. This is new release/QA surface: a kernel update on the customer box can require a module rebuild.",
    "",
    "##Recommendation for either path",
    "Ship full upgrades as a versioned, signed bundle (Stage-A artifacts + Stage-B packed tree) with a tested rollback (retain the previous tree + key). Treat the deployment key as a release secret with factory TPM-sealing as the field backstop.",
], body_size=14)

# ════════════════ SECTION 6: SECURITY / WRAP-UP ════════════════
section_slide(prs, 6, "Security posture, trade-offs & recommendation",
              "Everything the project decision hinges on")

content_slide(prs, "Threat model (agreed) — keep it in view", [
    "##At-box adversary = the client/operator",
    "Physically owns the hardware but is NON-TECHNICAL: GUI buttons, drag-and-drop, copy-to-USB. No concept of root, mounts, decryption, or memory forensics. Attack = 'copy the software folder and hand it to someone.'",
    "",
    "##Capable adversary = the competitor",
    "Expert reverse-engineers, but DECOUPLED from the live appliance — they only ever receive the bits the operator copied, never root on a running box.",
    "",
    "##Therefore the whole problem reduces to:",
    "'What a non-technical user can copy via GUI/USB must be ciphertext.'",
    "Sophisticated root-on-live-box attacks are genuinely out of scope: the person at the box can't do them, and the person who can isn't at the box.",
], body_size=15)

two_col_slide(prs, "Security scorecard against that threat model",
    "Current  (memfd + daemon)",
    [
        "Operator copies lib folder → keyless ciphertext.",
        "  Strong: key is NOT in the lib files.",
        "Operator copies an exe → ciphertext + key inside,",
        "  but bound to the launcher; not a clean binary.",
        "Plaintext only in RAM memfds; visible memfd",
        "  artifacts hint 'something is protected'.",
        "",
        "Residual: key concentrated in the exe/daemon —",
        "  hardening = obfuscation + TPM seal.",
        "Maturity: production-proven at full scale.",
    ],
    "kmod2  (antirevfs)",
    [
        "Operator copies via the mount → unauthorized",
        "  reader gets key-stripped ciphertext (useless).",
        "Operator copies the .enc/ tree directly →",
        "  DECRYPTABLE (key embedded). MUST be hidden in",
        "  an isolated mount namespace + access gate.",
        "No memfd artifact; real paths look ordinary.",
        "",
        "Residual: embedded key is the weak point —",
        "  hardening = wrap/seal the per-file key (TODO).",
        "Maturity: PoC, validated on real targets.",
    ], body_size=12)

content_slide(prs, "Recommendation & next steps", [
    "##Keep the current memfd+daemon design as the shipping path",
    "It is production-proven, fully userspace (no customer-kernel coupling), and its at-rest posture is strong: the bulk of the deployment (550 libs) is keyless ciphertext.",
    "",
    "##Continue kmod2 as the strategic candidate",
    "It is dramatically simpler to integrate (no shims, no dependency-ordering workarounds, binaries untouched) and leaves no memfd fingerprint. Its main gap is the embedded key + the kernel-module lifecycle.",
    "",
    "##To make kmod2 release-ready, close these:",
    "  1. Harden the embedded key — obfuscate / TPM-seal the per-file trailer so a copied .enc/ tree is also undecryptable",
    "  2. Module signing for Secure Boot + DKMS .deb/.rpm packaging",
    "  3. Promote the access-gate from allow-list (demo) to signature-based authorization",
    "  4. Validate the Docker / container-namespace path for the ARM64-on-x86 RTOS slave",
    "",
    "##For BOTH: factory TPM-seal the per-unit key",
    "This is the single highest-leverage control — it makes any exfiltrated ciphertext useless off the original hardware.",
], body_size=13)

# Closing
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide, BG_DARK)
shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.5), Inches(2.7), Inches(2), Pt(4))
shape.fill.solid(); shape.fill.fore_color.rgb = ACCENT; shape.line.fill.background()
tb = add_textbox(slide, Inches(1.5), Inches(1.2), Inches(7.5), Inches(1.4))
set_text(tb.text_frame, "One-line summary", size=34, color=WHITE, bold=True)
tb = add_textbox(slide, Inches(1.5), Inches(3.0), Inches(7.8), Inches(4.0))
tf = tb.text_frame; tf.word_wrap = True
set_text(tf, "Current design = proven, userspace, key hidden in executables, libs keyless — keep shipping it.",
         size=18, color=LIGHT)
add_para(tf, "", size=8)
add_para(tf, "kmod2 = simpler & cleaner, key embedded per file — promising once the key is hardened and the kernel module is signed/packaged.",
         size=18, color=LIGHT)
add_para(tf, "", size=8)
add_para(tf, "For both: the deployment key is the crown jewel — vault it in release, TPM-seal it per unit in the factory.",
         size=18, color=ACCENT2, bold=True)

# ── Save ────────────────────────────────────────────────────────────
import os
out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "kmod2_vs_daemon_report.pptx")
prs.save(out)
print("Saved:", out, "—", len(prs.slides._sldIdLst), "slides")
