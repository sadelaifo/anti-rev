# Build the shippable static mount helpers.  Static so they run on any x86-64
# client box regardless of its glibc version; carry no shell commentary.
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wno-format-truncation
# -s strips the symbol table (function/var names) from the link.
# --gc-sections drops unreferenced code/data (fewer stray strings, smaller bin).
LDFLAGS ?= -static -s -Wl,--gc-sections
SECFLAGS ?= -ffunction-sections -fdata-sections

# vcache-mount           : minimal single-tree ro/rw helper (explicit args)
# vcache-mount-inplace   : compiled twin of vcache-mount.sh (--mode real|sim,
#                          up|down|status|watch; in-place mounts + tmpfs layers;
#                          sim reaches the container via docker inspect + setns)
#
# NOTE on `strings`: a STATIC binary always contains libc's own strings, so the
# output is never empty.  Symbol stripping (above) removes OUR function names,
# but OUR string literals (paths, "vcachefs", "docker", gate-param names, log
# text) still appear.  To keep those out of `strings` too, compile-time string
# obfuscation is required (see the OBF layer / obfgen when enabled).  Verify:
#     strings vcache-mount-inplace | grep -iE 'vcachefs|proj|docker|gate_' || echo clean
all: vcache-mount vcache-mount-inplace

vcache-mount: vcache-mount.c
	$(CC) $(CFLAGS) $(SECFLAGS) $(LDFLAGS) -o $@ $<

vcache-mount-inplace: vcache-mount-inplace.c
	$(CC) $(CFLAGS) $(SECFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f vcache-mount vcache-mount-inplace
.PHONY: all clean
