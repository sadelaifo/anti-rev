# Build the shippable mount helpers.  Dynamically linked (against the target's
# own glibc); carry no shell commentary.  For a self-contained binary that runs
# regardless of the box's glibc version, override:  make LDFLAGS='-static -s -Wl,--gc-sections'
CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wno-format-truncation
# -s strips the symbol table; --gc-sections drops unreferenced code/data.
LDFLAGS  ?= -s -Wl,--gc-sections
SECFLAGS ?= -ffunction-sections -fdata-sections

# obfstr string-obfuscation layer (shared with the stub build):
#   stub/obfstr.h        — runtime XOR decoder + OBFSTR() marker
#   tools/obfstr_gen.py  — codegen: rewrites OBFSTR("x")/scanned-call literals
#                          into pre-encrypted _OBF(0x..) bytes before gcc
STUB    := ../../stub
OBFGEN  := ../../tools/obfstr_gen.py
OBFDIR  := obf
PY      ?= python3

all: vcache-mount vcache-mount-inplace

# Minimal single-tree ro/rw helper (explicit args) — not obfuscated.
vcache-mount: vcache-mount.c
	$(CC) $(CFLAGS) $(SECFLAGS) $(LDFLAGS) -o $@ $<

# Compiled twin of vcache-mount.sh.  Its string literals are XOR-obfuscated:
# obfstr_gen.py rewrites this source into $(OBFDIR)/ with encrypted bytes, then
# gcc compiles THAT against stub/obfstr.h.  Result: `strings` shows none of our
# design tokens (a dynamic binary still shows a few loader refs like libc.so.6
# and imported symbol names — never our literals).  Verify:
#   strings vcache-mount-inplace | grep -iE 'vcachefs|proj|docker|gate_|AREV_|passdata' || echo clean
# If python3 is missing the raw source still compiles (OBFSTR is a passthrough),
# but the literals are NOT hidden — a loud warning is printed.
$(OBFDIR)/vcache-mount-inplace.c: vcache-mount-inplace.c $(OBFGEN)
	@if command -v $(PY) >/dev/null 2>&1; then \
	   echo "obfstr-codegen vcache-mount-inplace.c"; \
	   $(PY) $(OBFGEN) --out-dir $(OBFDIR) $< ; \
	 else \
	   echo "WARNING: $(PY) not found -> building WITHOUT string obfuscation (strings WILL leak)"; \
	   mkdir -p $(OBFDIR) && cp $< $(OBFDIR)/ ; \
	 fi

vcache-mount-inplace: $(OBFDIR)/vcache-mount-inplace.c
	$(CC) $(CFLAGS) $(SECFLAGS) -I$(STUB) $(LDFLAGS) -o $@ $<

clean:
	rm -f vcache-mount vcache-mount-inplace
	rm -rf $(OBFDIR)
.PHONY: all clean
