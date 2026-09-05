# Build the shippable static mount helper.  Static so it runs on any x86-64
# client box regardless of its glibc version; carries no shell commentary.
CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wno-format-truncation
vcache-mount: vcache-mount.c
	$(CC) $(CFLAGS) -static -o $@ $<
clean:
	rm -f vcache-mount
.PHONY: clean
