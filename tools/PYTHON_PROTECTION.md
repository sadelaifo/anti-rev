# Python-side protection: invisible activation + binary client

This explains the **"zero-source-change" Python protection flow** —
how to make `antirev_client` activate automatically for protected
business scripts, without touching any of their source code, and ship
the client as a compiled `.so` instead of a readable `.py`.

## What problem it solves

Before this flow, every Python script that needed encrypted libraries
had to start with:

```python
import sys
sys.path.insert(0, "/path/to/tools")
from antirev_client import activate
activate("/path/to/.lrxd")
# ...
```

That has two issues:

1. **Source-level intrusion** — every business script gets antirev
   tattoos at line 1, hundreds or thousands of files touched
2. **Plaintext leakage** — `antirev_client.py` sits readable on disk
   and exposes the daemon protocol, hook strategy, and design
   intent

This flow fixes both.

## The mechanism, one paragraph

CPython's `site.py` reads every `*.pth` file in each site-packages
directory at interpreter startup, **before** any user script runs.
Lines beginning with `import ` (note the trailing space) are passed
to `exec()`.  We exploit this with a single-line `antirev.pth`:

```
import antirev_client; antirev_client._safe_activate()
```

`_safe_activate()` is the gated entry point — it consults
`ANTIREV_DIRS` / `ANTIREV_ENABLE` / `ANTIREV_DISABLE` env vars and
decides whether the current process should actually have antirev
hooks installed.  Unrelated Python invocations (pip, system tools,
ad-hoc scripts outside the protected install) get a fast no-op.

The client itself is shipped as a compiled extension —
`antirev_client.cpython-3X-<arch>-linux-gnu.so` — produced by
`tools/build_antirev_client.py`.  No `antirev_client.py` ever lands
on the target host.

## Deployment

### 1. Compile the client

On a machine of the same arch as the target (or a cross-compile
host):

```
python tools/build_antirev_client.py
```

Outputs:

```
tools/antirev_client.cpython-3X-<arch>-linux-gnu.so   # the compiled module
tools/antirev.pth                                     # the .pth (in repo already)
```

### 2. Find the target site-packages

On the target host:

```
python -c "import site; print('\n'.join(site.getsitepackages()))"
```

This prints the site-packages directories the target's Python scans.
Use whichever is appropriate (usually the system one for system-wide
deployment, or the venv's for a sandboxed business app).

### 3. Install

```
cp tools/antirev_client.cpython-3X-<arch>-linux-gnu.so  <target-site-packages>/
cp tools/antirev.pth                                    <target-site-packages>/
```

Do **NOT** copy `antirev_client.py` itself — Python prefers the
compiled extension when both are present, but shipping the source
defeats the purpose of compiling.

### 4. Configure which scripts get protected

Set the `ANTIREV_DIRS` env var (colon-separated on Linux,
semicolon-separated on Windows) in your business launcher / systemd
unit / wrapper script:

```bash
# /opt/your-app/bin/run.sh
export ANTIREV_DIRS=/opt/your-app/scripts:/opt/your-app/lib/python
exec /usr/bin/python3 "$@"
```

Or set it system-wide if your protected scripts always live under a
known prefix.

Now any Python script under those directories triggers `activate()`
automatically at interpreter startup.  Scripts outside (pip, system
tools, ad-hoc scripts) see no antirev side effects.

## Env vars

| Var | Effect | Use case |
|---|---|---|
| `ANTIREV_DIRS` | os.pathsep-separated list of dirs.  Scripts whose path resolves under any of these directories trigger auto-activation. | Production deployment |
| `ANTIREV_ENABLE=1` | Force auto-activation regardless of script path. | Testing, ad-hoc runs |
| `ANTIREV_DISABLE=1` | Disable auto-activation regardless of everything else. | Debugging, emergency disable |
| `ANTIREV_KEY` | Path to key file or daemon binary (consumed by `activate()` itself, not by the gating logic). | Required for activate() to find the key |
| `ANTIREV_TMP_PREFIX` | Prefix for the symlink tempdir under `/tmp/`.  Default `.lrx_`. | Branding / fingerprint avoidance |
| `__r_NP=1` | "No-preload" mode — see `activate()` docstring. | Workaround for libs with implicit DT_NEEDED |

## Verifying the install

```bash
# Check that the .pth is picked up at startup
python -c "import sys; print('antirev_client' in sys.modules)"
# Expect: False (because ANTIREV_DIRS isn't set yet — gated off)

ANTIREV_ENABLE=1 ANTIREV_KEY=/path/to/.lrxd python -c \
    "import sys; print('antirev_client' in sys.modules)"
# Expect: True
```

Check that the compiled .so is being picked up over any leftover .py:

```bash
ANTIREV_ENABLE=1 ANTIREV_KEY=/path/to/.lrxd python -c \
    "import antirev_client; print(antirev_client.__file__)"
# Expect: ...antirev_client.cpython-3X-*.so
# If it shows .py, the .so isn't in this Python's path.
```

## Backward compatibility

The change is fully backward compatible:

- Existing tests / demos that do `from antirev_client import
  activate` and call `activate()` directly continue to work — that
  path bypasses `_should_activate()` entirely
- The `.pth` and self-gating logic are purely additive
- The compiled `.so` exports the same public surface as the `.py`,
  so any code that imports `antirev_client.AntirevClient` or
  `activate` works identically

## What this does NOT hide

Even with full compilation + .pth deployment, these remain visible:

- The `.pth` file itself is plaintext — but only contains
  `import antirev_client; antirev_client._safe_activate()`, no
  internal details
- `nm` / `readelf` on the .so shows exported symbol names like
  `activate`, `AntirevClient`
- `sys.meta_path` after activation reveals that a custom finder is
  installed (visible to anything with Python execution in the same
  process)
- Symlink directory under `/tmp/.lrx_*` is still observable via `ls`

These are architecture-level fingerprints, not crypto-level secrets.
The actual encryption keys, decrypted contents, and daemon protocol
state remain protected by the existing C-level mechanisms (memfd,
LD_PRELOAD shim, kernel-enforced fd boundaries).

## When to skip this flow

- If your deployment has only one Python script and you don't mind
  the `from antirev_client import activate; activate()` line at its
  top, the explicit-import flow is fine
- If you ship a fully bundled Python (Nuitka standalone, PyInstaller,
  etc.) the .pth mechanism doesn't apply — bundle activation into
  the bundle's startup instead
