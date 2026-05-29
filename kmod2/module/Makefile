# SPDX-License-Identifier: GPL-2.0
# Kbuild for the antirevfs out-of-tree kernel module.
#
#   make            # build against the running kernel
#   make KDIR=/lib/modules/<ver>/build
#   make clean

obj-m += antirevfs.o
antirevfs-objs := super.o inode.o file.o crypto.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# The module must be built with the same compiler the kernel was built with.
# Pass CC explicitly if your default toolchain differs, e.g. `make CC=gcc-12`.
MAKE_ARGS := $(if $(CC),CC=$(CC))

all:
	$(MAKE) -C $(KDIR) M=$(PWD) $(MAKE_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
