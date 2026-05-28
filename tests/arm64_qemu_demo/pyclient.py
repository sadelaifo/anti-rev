#!/usr/bin/env python3
# Python integration: load an encrypted aarch64 .so via antirev_client.py
# under qemu.  Mirrors the business suite's 1000+ python scripts that
# dlopen encrypted libs through the daemon.  ctypes.CDLL is transparently
# redirected to the daemon-served memfd; libplugin's encrypted DT_NEEDED
# (libcore) is pulled through the closure.
import sys, os
sys.path.insert(0, "/root/antirev/tools")
import antirev_client
antirev_client.activate()
import ctypes
lib = ctypes.CDLL("libplugin.so")
r = lib.plugin_run()
print(f"[pyclient] plugin_run() = {r} (expect 84)")
sys.exit(0 if r == 84 else 3)
