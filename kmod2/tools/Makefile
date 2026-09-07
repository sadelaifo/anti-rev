# Build the shippable static mount helpers.  Static so they run on any x86-64
# client box regardless of its glibc version; carry no shell commentary.
CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wno-format-truncation

# vcache-mount           : minimal single-tree ro/rw helper (explicit args)
# vcache-mount-inplace   : compiled twin of vcache-mount.sh (--mode real|sim,
#                          up|down|status|watch; in-place mounts + tmpfs layers;
#                          sim reaches the container via docker inspect + setns)
all: vcache-mount vcache-mount-inplace

vcache-mount: vcache-mount.c
	$(CC) $(CFLAGS) -static -o $@ $<

vcache-mount-inplace: vcache-mount-inplace.c
	$(CC) $(CFLAGS) -static -o $@ $<

clean:
	rm -f vcache-mount vcache-mount-inplace
.PHONY: all clean
