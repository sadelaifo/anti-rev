# hotpatch demo (aarch64)

A minimal target to verify the aarch64 hot-patch path end to end:
`main` loops every second calling `say_hello()` and logging which version
ran. Apply the encrypted `.pat` built from `patch_v2.c`, and the log
should switch from **ORIGINAL (v1)** to **PATCHED (v2!)** with no restart.

## Files
- `demo.c` — target program: `main` loop + `say_hello()` (the patch target).
- `patch_v2.c` — the new `say_hello()`; compiled to a `.o` = the patch object.

## Flow

```sh
# 1. Build the target (adjust flags to your PatchActive's requirements)
aarch64-linux-gnu-gcc -O0 -fno-inline -fpatchable-function-entry=2 \
    -no-pie -o demo demo.c

# 2. Build the patch object
aarch64-linux-gnu-gcc -O0 -fno-inline -c -o say_hello.o patch_v2.c
cp say_hello.o say_hello.pat        # name it what your loader opens

# 3. Encrypt the .pat into the daemon's scan tree (keysplit-derived key)
python3 ../../encryptor/protect.py encrypt-patch \
    --key <part1.key> --lrxd <deployed lrxd-aarch64> --version <version.sh> \
    --patches say_hello.pat --output-dir <daemon-scan-dir>

# 4. Run the target with the patch shim preloaded so its readFile of the
#    .pat is transparently decrypted (LD_PRELOAD order: lrxd BEFORE
#    antirev_shim on aarch64 — see CLAUDE.md "Intercepted opens").
LD_PRELOAD=<deployed>/lrxd_aarch64.so ANTIREV_PATCH_LOG=/tmp/patch.log ./demo

# 5. In another shell, trigger your PatchFetch/PatchActive against the
#    running demo. Watch demo's stdout flip v1 -> v2.
```

## Expected output

```
[demo] started pid=12345 — calling say_hello() every 1s
[demo] call #1 -> ORIGINAL say_hello (v1)
[demo] call #2 -> ORIGINAL say_hello (v1)
...                                            <-- patch applied here
[demo] call #7 -> PATCHED say_hello (v2!)  <-- hot patch live
[demo] call #8 -> PATCHED say_hello (v2!)  <-- hot patch live
```

## Adjust to your loader

The `main`/`say_hello`/logging part is generic. The **compile flags** and
**how the patch is applied** depend on your `PatchFetch`/`PatchActive`:

- `-fpatchable-function-entry=N` / `-no-pie` / symbol visibility — set to
  whatever makes `say_hello` a redirectable target for your patcher.
- `.pat` filename and how the loader locates the target function — match
  your PatchActive's contract.

Tell me your PatchFetch/PatchActive interface (how it takes the `.pat`
buffer and which function it redirects) and I'll wire step 5 into a real
driver so the demo is fully self-running.
