#!/usr/bin/env python3
"""
Demo: Python dlopen through encrypted → unencrypted → encrypted chain.

Topology:
  Python ──dlopen──→ libfoo.so (encrypted)
                         │
                     DT_NEEDED
                         ↓
                     libbar.so  (unencrypted)
                         │
                     DT_NEEDED
                         ↓
                     libtee.so  (encrypted)

Assumes antirev-libd is already running with the encrypted libs decrypted.

Usage:
    python3 demo.py [path-to-.antirev-libd-or-key]
"""

import sys
import os
import ctypes

# Add tools/ to path so we can import antirev_client
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from antirev_client import activate


def main():
    key_source = sys.argv[1] if len(sys.argv) > 1 else None
    client = activate(key_source)

    print(f"Available libs: {sorted(client.libs.keys())}")

    # dlopen libfoo.so — it DT_NEEDs libbar.so (unencrypted),
    # which DT_NEEDs libtee.so (encrypted).
    # activate() already preloaded all encrypted libs with RTLD_GLOBAL,
    # so libtee.so symbols are available when libbar.so loads.
    lib = ctypes.CDLL("libfoo.so")
    lib.foo_result.restype = ctypes.c_int
    result = lib.foo_result()

    expected = 1556  # tee_value(777) + 1 = 778, * 2 = 1556
    if result == expected:
        print(f"PASS: foo_result() = {result}")
    else:
        print(f"FAIL: foo_result() = {result}, expected {expected}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
