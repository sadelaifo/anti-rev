"""
antirev_client — Python client for the antirev lib daemon.

Connects to the running antirev-libd daemon, receives decrypted lib
fds via SCM_RIGHTS, and provides ctypes.CDLL loading.  No pip
dependencies — uses system libcrypto via ctypes.

Usage (explicit):
    from antirev_client import AntirevClient

    client = AntirevClient("/path/to/antirev.key")
    lib = client.cdll("libFoo.so")   # returns ctypes.CDLL
    fd  = client.fd("libFoo.so")     # returns raw fd number

    # List available libs:
    print(client.libs)

Usage (auto-patch — for scripts that call ctypes.CDLL directly):
    from antirev_client import activate

    activate("/path/to/.antirev-libd")  # or key file

    # Now ctypes.CDLL transparently loads encrypted libs:
    import ctypes
    lib = ctypes.CDLL("libFoo.so")  # redirected to memfd

Key source discovery for activate():
    1. Explicit path argument
    2. ANTIREV_KEY env var (path to key file or daemon binary)
    3. .antirev-libd in the script's directory
"""

import array
import ctypes as ct
import ctypes.util
import os
import socket
import struct
import sys
from pathlib import Path

KEY_SIZE = 32
SCM_BATCH = 250


# ── ELF DT_NEEDED parser (pure Python, no external tools) ──────────

def _parse_elf_needed(f):
    """Parse DT_NEEDED entries from an open ELF file object."""
    f.seek(0)
    ident = f.read(16)
    if ident[:4] != b'\x7fELF':
        return []
    is64 = (ident[4] == 2)

    # Read e_phoff, e_phentsize, e_phnum
    if is64:
        f.seek(32); e_phoff = struct.unpack('<Q', f.read(8))[0]
        f.seek(54); e_phentsize, e_phnum = struct.unpack('<HH', f.read(4))
    else:
        f.seek(28); e_phoff = struct.unpack('<I', f.read(4))[0]
        f.seek(42); e_phentsize, e_phnum = struct.unpack('<HH', f.read(4))

    # Read all program headers
    f.seek(e_phoff)
    phdrs = f.read(e_phentsize * e_phnum)

    # Find PT_DYNAMIC and collect PT_LOAD segments
    dyn_off = dyn_sz = 0
    loads = []
    for i in range(e_phnum):
        base = i * e_phentsize
        p_type = struct.unpack_from('<I', phdrs, base)[0]
        if is64:
            p_off = struct.unpack_from('<Q', phdrs, base + 8)[0]
            p_va = struct.unpack_from('<Q', phdrs, base + 16)[0]
            p_fsz = struct.unpack_from('<Q', phdrs, base + 32)[0]
        else:
            p_off = struct.unpack_from('<I', phdrs, base + 4)[0]
            p_va = struct.unpack_from('<I', phdrs, base + 8)[0]
            p_fsz = struct.unpack_from('<I', phdrs, base + 16)[0]
        if p_type == 2:  # PT_DYNAMIC
            dyn_off, dyn_sz = p_off, p_fsz
        elif p_type == 1:  # PT_LOAD
            loads.append((p_va, p_off, p_fsz))

    if not dyn_off:
        return []

    # Parse dynamic entries → find DT_NEEDED offsets and DT_STRTAB addr
    f.seek(dyn_off)
    dyn = f.read(dyn_sz)
    esz = 16 if is64 else 8
    fmt = '<qQ' if is64 else '<iI'

    needed_offs = []
    strtab_va = 0
    for i in range(0, len(dyn), esz):
        d_tag, d_val = struct.unpack_from(fmt, dyn, i)
        if d_tag == 0:
            break
        if d_tag == 1:   # DT_NEEDED
            needed_offs.append(d_val)
        elif d_tag == 5:  # DT_STRTAB
            strtab_va = d_val

    if not needed_offs or not strtab_va:
        return []

    # Convert strtab virtual address → file offset via PT_LOAD
    strtab_foff = 0
    for va, foff, fsz in loads:
        if va <= strtab_va < va + fsz:
            strtab_foff = foff + (strtab_va - va)
            break
    if not strtab_foff:
        return []

    # Read null-terminated strings
    names = []
    for off in needed_offs:
        f.seek(strtab_foff + off)
        raw = b''
        while True:
            c = f.read(1)
            if not c or c == b'\x00':
                break
            raw += c
        names.append(raw.decode())
    return names


def _get_needed(fd):
    """Parse DT_NEEDED entries from an ELF at /proc/self/fd/<fd>."""
    with open(f"/proc/self/fd/{fd}", 'rb') as f:
        return _parse_elf_needed(f)


def _get_needed_from_path(path):
    """Parse DT_NEEDED entries from an ELF file on disk."""
    try:
        with open(path, 'rb') as f:
            return _parse_elf_needed(f)
    except OSError:
        return []


# ── AES helper (system libcrypto, no pip deps) ──────────────────────

def _aes256_ecb_block(key, block):
    """AES-256-ECB encrypt one 16-byte block using system libcrypto."""
    path = ct.util.find_library("crypto") or "libcrypto.so.3"
    lib = ct.CDLL(path)

    _vp = ct.c_void_p
    _cp = ct.c_char_p
    _ip = ct.POINTER(ct.c_int)

    lib.EVP_CIPHER_CTX_new.restype = _vp
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_aes_256_ecb.restype = _vp
    lib.EVP_aes_256_ecb.argtypes = []
    lib.EVP_EncryptInit_ex.argtypes = [_vp, _vp, _vp, _cp, _cp]
    lib.EVP_CIPHER_CTX_set_padding.argtypes = [_vp, ct.c_int]
    lib.EVP_EncryptUpdate.argtypes = [_vp, _cp, _ip, _cp, ct.c_int]
    lib.EVP_CIPHER_CTX_free.argtypes = [_vp]

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = lib.EVP_aes_256_ecb()
        lib.EVP_EncryptInit_ex(ctx, cipher, None, key, None)
        lib.EVP_CIPHER_CTX_set_padding(ctx, 0)

        out = ct.create_string_buffer(32)
        outlen = ct.c_int(0)
        lib.EVP_EncryptUpdate(ctx, out, ct.byref(outlen), block, len(block))
        return out.raw[:outlen.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def _compute_sock_name(key):
    """Derive the daemon's abstract socket name from the key.

    Matches stub.c make_sock_addr(): AES_K(0^16)[0:8] → hex.
    """
    h = _aes256_ecb_block(key, b'\x00' * 16)
    return "antirev_" + h[:8].hex()


# ── Key loading ─────────────────────────────────────────────────────

def _load_key(path):
    """Load 32-byte key from hex file or daemon/stub trailer."""
    data = path.read_bytes()

    # Check if it's a binary with ANTREV01 trailer (last 48 bytes)
    if len(data) > 48 and data[-8:] == b"ANTREV01":
        return data[-40:-8]

    # Otherwise treat as hex text
    hex_str = data.decode().strip()
    key = bytes.fromhex(hex_str)
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes ({KEY_SIZE * 2} hex chars)")
    return key


# ── Client ──────────────────────────────────────────────────────────

class AntirevClient:
    """Client for the antirev lib daemon.

    Args:
        key_source: path to key file (hex) or any antirev stub/daemon
                    binary (key is extracted from the ANTREV01 trailer).
    """

    def __init__(self, key_source):
        self._key = _load_key(Path(key_source))
        self._libs = {}
        self._connect()

    def _connect(self):
        sock_name = _compute_sock_name(self._key)
        sd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sd.connect(b'\x00' + sock_name.encode())
            self._receive_libs(sd)
        finally:
            sd.close()

    def _receive_libs(self, sd: socket.socket):
        """Receive batched lib fds via SCM_RIGHTS."""
        while True:
            fds = array.array('i')
            msg, ancdata, _, _ = sd.recvmsg(
                65536, socket.CMSG_SPACE(SCM_BATCH * fds.itemsize))

            if len(msg) < 4:
                break

            nlibs = struct.unpack_from('<I', msg, 0)[0]
            if nlibs == 0:
                break

            # Extract fds
            received_fds = []
            for cmsg_level, cmsg_type, cmsg_data in ancdata:
                if (cmsg_level == socket.SOL_SOCKET
                        and cmsg_type == socket.SCM_RIGHTS):
                    batch_fds = array.array('i')
                    batch_fds.frombytes(cmsg_data[:nlibs * batch_fds.itemsize])
                    received_fds = list(batch_fds)

            # Parse names
            off = 4
            for i in range(nlibs):
                if off + 2 > len(msg):
                    break
                nlen = struct.unpack_from('<H', msg, off)[0]
                off += 2
                name = msg[off:off + nlen].decode()
                off += nlen
                if i < len(received_fds):
                    self._libs[name] = received_fds[i]

    @property
    def libs(self):
        """Dict of available libs: {name: fd}."""
        return dict(self._libs)

    def fd(self, name):
        """Get the memfd number for a lib by name."""
        if name not in self._libs:
            avail = ', '.join(sorted(self._libs))
            raise KeyError(f"'{name}' not found (available: {avail})")
        return self._libs[name]

    def cdll(self, name, mode=ct.DEFAULT_MODE):
        """Load an encrypted lib as ctypes.CDLL."""
        return ct.CDLL(f"/proc/self/fd/{self.fd(name)}", mode=mode)

    def preload_all(self):
        """Load ALL daemon libs with RTLD_GLOBAL in dependency order.

        Mirrors the C stub's LD_PRELOAD behavior: all libs are globally
        available so implicit cross-lib symbol references resolve.
        Uses DT_NEEDED to topologically sort — leaves first, so each
        lib's constructor finds its deps already loaded.

        Follows DT_NEEDED through unencrypted intermediaries on disk
        (e.g. encrypted A → unencrypted B → encrypted C) so that C
        is loaded before A.
        """
        fd_map = self._libs
        _RealCDLL = getattr(ct.CDLL, '_antirev_real', ct.CDLL)
        loaded = set()

        def _resolve_disk(name):
            """Find an unencrypted lib on disk, return path or None."""
            disk_path = ct.util.find_library(
                name.replace('lib', '', 1).split('.so')[0])
            if not disk_path:
                for d in os.environ.get('LD_LIBRARY_PATH', '').split(':'):
                    candidate = os.path.join(d, name) if d else None
                    if candidate and os.path.isfile(candidate):
                        return candidate
            return disk_path

        def _load(name):
            if name in loaded:
                return
            loaded.add(name)
            if name in fd_map:
                # Encrypted lib — parse deps from the memfd
                for dep in _get_needed(fd_map[name]):
                    _load(dep)
                _RealCDLL(f"/proc/self/fd/{fd_map[name]}",
                          mode=ct.RTLD_GLOBAL)
            else:
                # Unencrypted intermediary — find on disk via ctypes
                # and follow its DT_NEEDED to discover encrypted deps
                disk_path = _resolve_disk(name)
                if disk_path:
                    for dep in _get_needed_from_path(disk_path):
                        _load(dep)

        # Sort: load libs with fewer DT_NEEDED entries first.  Libs
        # with fewer deps are more likely "providers" (leaf libs) and
        # should be globally available before "consumer" libs whose
        # constructors might dlopen other libs at init time.  This
        # mirrors LD_PRELOAD semantics where all libs are mapped before
        # any constructor runs — ctypes.CDLL runs constructors
        # immediately, so order matters.
        dep_count = {}
        for name in fd_map:
            dep_count[name] = len(_get_needed(fd_map[name]))
        load_order = sorted(fd_map, key=lambda n: (dep_count[n], n))

        for name in load_order:
            _load(name)

        self._preloaded = {n for n in loaded if n in fd_map}

    def patch_ctypes(self):
        """Monkey-patch ctypes.CDLL to redirect encrypted lib loads."""
        fd_map = self._libs
        _RealCDLL = getattr(ct.CDLL, '_antirev_real', ct.CDLL)

        class _PatchedCDLL(_RealCDLL):
            _antirev_real = _RealCDLL

            def __init__(self, name, *args, **kwargs):
                if name:
                    base = name.rsplit('/', 1)[-1]
                    if base in fd_map:
                        name = f"/proc/self/fd/{fd_map[base]}"
                super().__init__(name, *args, **kwargs)

        ct.CDLL = _PatchedCDLL
        ct.cdll._dlltype = _PatchedCDLL


# ── Auto-patch helper ──────────────────────────────────────────────

def _find_key_source():
    """Find key source: ANTIREV_KEY env, or .antirev-libd near caller."""
    env = os.environ.get("ANTIREV_KEY")
    if env:
        p = Path(env)
        if p.exists():
            return p
        raise FileNotFoundError(f"ANTIREV_KEY={env} does not exist")

    # Search near the calling script
    main = getattr(sys.modules.get("__main__"), "__file__", None)
    if main:
        candidate = Path(main).resolve().parent / ".antirev-libd"
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "Cannot find antirev key. Set ANTIREV_KEY env var or place "
        ".antirev-libd next to your script."
    )


def activate(key_source=None):
    """Connect to daemon and patch ctypes.CDLL for transparent loading.

    Args:
        key_source: path to key file or daemon binary. If None,
                    auto-discovers via ANTIREV_KEY env or .antirev-libd.

    Returns:
        The AntirevClient instance (for introspection / manual use).
    """
    if key_source is None:
        key_source = _find_key_source()
    client = AntirevClient(key_source)
    client.preload_all()
    client.patch_ctypes()
    print(f"[antirev] loaded {len(client._preloaded)} libs, ctypes.CDLL patched",
          file=sys.stderr)
    return client
