# fusefs / vcachefsd — userspace decrypt-on-read FUSE daemon (antirev design 3).
#
#   make              # dynamic build (needs libfuse3 + openssl dev packages)
#   make static       # static binary for shipping in a Docker image
#   make clean
#
# Deps (dev boxes):  Debian/Ubuntu: libfuse3-dev libssl-dev
#                    SLES/openSUSE:  fuse3-devel  libopenssl-devel
# Runtime: stock kernel 'fuse' + /dev/fuse (no custom module, no vermagic).

CC      ?= cc
SRCDIR  := src
SRCS    := $(SRCDIR)/fs.c $(SRCDIR)/container.c $(SRCDIR)/crypto.c \
           $(SRCDIR)/gate.c $(SRCDIR)/cache.c
BIN     := vcachefsd

PKG_CFLAGS := $(shell pkg-config --cflags fuse3 openssl 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs   fuse3 openssl 2>/dev/null)

# Fallbacks if pkg-config is unavailable.
PKG_CFLAGS ?= -I/usr/include/fuse3 -D_FILE_OFFSET_BITS=64
PKG_LIBS   ?= -lfuse3 -lssl -lcrypto -lpthread

CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra -std=gnu11 $(PKG_CFLAGS)
LDLIBS  += $(PKG_LIBS) -lpthread

.PHONY: all static clean
all: $(BIN)

$(BIN): $(SRCS) $(SRCDIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

# Static build for shipping inside a container image.  Requires static libfuse3
# + openssl archives (libfuse3.a, libssl.a, libcrypto.a) to be installed.
static: $(SRCS) $(SRCDIR)/*.h
	$(CC) $(CFLAGS) -static -o $(BIN) $(SRCS) \
	    $(shell pkg-config --static --libs fuse3 openssl 2>/dev/null) \
	    -lpthread -ldl

clean:
	rm -f $(BIN)
