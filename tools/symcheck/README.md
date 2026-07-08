# symcheck — dlsym ownership-flip detector

Validates that encrypting the business software with **memfd+daemon** does not
change **which DSO owns a symbol resolved at runtime via `dlsym()`**.

## Why this is a separate tool from `LD_DEBUG`

`LD_DEBUG=bindings` (with `LD_BIND_NOW=1`) captures every **relocation**-based
symbol resolution in every **loaded** DSO — call-independent, and complete for
that class. But a runtime `dlsym(handle, name)` — especially
`dlsym(RTLD_DEFAULT, …)` / `dlsym(RTLD_NEXT, …)` — is performed by the linker's
`_dl_sym` path and is **not** a relocation, so `LD_DEBUG` never logs it. Yet its
result is load-order / scope dependent and can therefore change when the same
binaries load via `/proc/self/fd/N` + the daemon instead of from disk. Apps that
`dlopen` plugins and then `dlsym` their entry points concentrate risk in exactly
this uncovered path.

`symcheck` fills the gap: intercept every `dlsym`, record the DSO that owns the
returned symbol (via `dladdr`), run the workload plaintext and encrypted, and
diff.

## Files

- `dlsym_intercept.c` — `LD_PRELOAD` shim. Logs `caller<TAB>kind<TAB>symbol<TAB>owner`,
  one line per `dlsym`. `kind` ∈ `DEFAULT` / `NEXT` / `HANDLE`. Owner and caller
  are basenames, so a memfd/daemon lib (reported by `dladdr` via its
  `/tmp/antirev_<pid>_xxx/<soname>` symlink path) lines up with the plaintext
  disk path. Coexists with `antirev_shim` (which interposes `dlopen`, not
  `dlsym`).
- `symdiff.py` — merges per-process logs and reports symbols whose owner set
  changed between the two runs. Exits non-zero on any flip (CI gate). Filters
  lookups made by `antirev_shim` itself unless `--include-shim`.

## Usage

```sh
# 1. build the interceptor
gcc -shared -fPIC -O2 -D_GNU_SOURCE \
    -o dlsym_intercept.so tools/symcheck/dlsym_intercept.c -ldl

# 2. run the SAME workload twice — plaintext, then encrypted — keeping every
#    antirev_shim entry that the encrypted run needs on LD_PRELOAD.
#    Use a per-process log path so multi-process suites don't collide.
LD_PRELOAD=./dlsym_intercept.so ANTIREV_DLSYM_LOG=plain/<svc> <workload-plaintext>
LD_PRELOAD=./dlsym_intercept.so:<antirev_shim.so> ANTIREV_DLSYM_LOG=enc/<svc> <workload-encrypted>

# 3. diff (each side is a file or a directory of per-process logs)
python3 tools/symcheck/symdiff.py plain enc
```

A `[CHANGED]` line means `dlsym` resolved `symbol` to a **different DSO** in the
encrypted run — the thing to investigate. `RTLD_DEFAULT`/`RTLD_NEXT` flips are
the high-risk cases; a `HANDLE` flip on a specific lib usually means a duplicate
lives in that lib's dependency scope.

## Coverage / limits

- **Call-generation matters.** `dlsym` coverage = the app's *actual* lookups, so
  drive the **real app** (init → steady state → shutdown); a synthetic driver
  can't fake the right `(handle, name)` pairs. Pair with the `LD_DEBUG` binding
  diff (relocations) for the full picture.
- Intercepts `dlsym` only. `dlvsym` (rare in business code) is not logged; the
  interceptor *uses* the real `dlvsym` to bootstrap the real `dlsym`.
- Owner is resolved from the returned address; a `<null>` owner means the lookup
  failed in that run (itself worth a look if it differs across runs).

## Test

`tests/symcheck/` + `test_dlsym_intercept` (in the suite) prove the tool
end-to-end without the daemon: the same two libs loaded in a different **order**
flip the `RTLD_DEFAULT` owner of `who`, which `symdiff.py` reports, while the
fixed-handle lookup stays stable (no false positive).
