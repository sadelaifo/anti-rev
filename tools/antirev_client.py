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
import tempfile
from pathlib import Path

KEY_SIZE = 32
SCM_BATCH = 250


# ── ELF DT_NEEDED parser (pure Python, no external tools) ──────────

def _parse_elf_dynamic(f):
    """Parse DT_NEEDED and DT_SONAME from an open ELF file object.

    Returns (needed_list, soname_or_None).
    """
    f.seek(0)
    ident = f.read(16)
    if ident[:4] != b'\x7fELF':
        return [], None
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
        return [], None

    # Parse dynamic entries → DT_NEEDED offsets, DT_SONAME, DT_STRTAB
    f.seek(dyn_off)
    dyn = f.read(dyn_sz)
    esz = 16 if is64 else 8
    fmt = '<qQ' if is64 else '<iI'

    needed_offs = []
    soname_off = None
    strtab_va = 0
    for i in range(0, len(dyn), esz):
        d_tag, d_val = struct.unpack_from(fmt, dyn, i)
        if d_tag == 0:
            break
        if d_tag == 1:   # DT_NEEDED
            needed_offs.append(d_val)
        elif d_tag == 5:  # DT_STRTAB
            strtab_va = d_val
        elif d_tag == 14:  # DT_SONAME
            soname_off = d_val

    if not strtab_va:
        return [], None

    # Convert strtab virtual address → file offset via PT_LOAD
    strtab_foff = 0
    for va, foff, fsz in loads:
        if va <= strtab_va < va + fsz:
            strtab_foff = foff + (strtab_va - va)
            break
    if not strtab_foff:
        return [], None

    def _read_str(off):
        f.seek(strtab_foff + off)
        raw = b''
        while True:
            c = f.read(1)
            if not c or c == b'\x00':
                break
            raw += c
        return raw.decode()

    names = [_read_str(off) for off in needed_offs]
    soname = _read_str(soname_off) if soname_off is not None else None
    return names, soname


def _get_needed(fd):
    """Parse DT_NEEDED entries from an ELF at /proc/self/fd/<fd>."""
    with open(f"/proc/self/fd/{fd}", 'rb') as f:
        return _parse_elf_dynamic(f)[0]


def _get_needed_from_path(path):
    """Parse DT_NEEDED entries from an ELF file on disk."""
    try:
        with open(path, 'rb') as f:
            return _parse_elf_dynamic(f)[0]
    except OSError:
        return []


def _get_soname(fd):
    """Parse DT_SONAME from an ELF at /proc/self/fd/<fd>."""
    with open(f"/proc/self/fd/{fd}", 'rb') as f:
        return _parse_elf_dynamic(f)[1]


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
        self._loaded = set()   # tracks libs processed by _ensure_loaded
        self._link_dir = tempfile.mkdtemp(prefix="antirev_")
        # Prepend symlink dir to LD_LIBRARY_PATH so glibc's DT_NEEDED
        # resolution finds our soname symlinks (→ memfd) before any
        # encrypted copies on disk.
        ld_path = os.environ.get('LD_LIBRARY_PATH', '')
        os.environ['LD_LIBRARY_PATH'] = self._link_dir + (':' + ld_path if ld_path else '')
        self._connect()
        self._build_soname_map()

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

    def _build_soname_map(self):
        """Map DT_SONAME → fd_map key for each encrypted lib.

        DT_NEEDED entries use sonames (e.g. "libB.so.1") but the daemon
        sends filenames (e.g. "libB.so.1.2.3").  This map lets
        _ensure_loaded resolve sonames to fd_map keys.
        """
        self._soname_to_key = {}
        for name, fd in self._libs.items():
            soname = _get_soname(fd)
            if soname and soname != name:
                self._soname_to_key[soname] = name

    @property
    def libs(self):
        """Dict of available libs: {name: fd}."""
        return dict(self._libs)

    def fd(self, name):
        """Get the memfd number for a lib by name."""
        key = self._soname_to_key.get(name, name)
        if key not in self._libs:
            avail = ', '.join(sorted(self._libs))
            raise KeyError(f"'{name}' not found (available: {avail})")
        return self._libs[key]

    def cdll(self, name, mode=ct.DEFAULT_MODE):
        """Load an encrypted lib as ctypes.CDLL."""
        return ct.CDLL(f"/proc/self/fd/{self.fd(name)}", mode=mode)

    @staticmethod
    def _resolve_disk(name):
        """Find an unencrypted lib on disk, return path or None."""
        # Prefer LD_LIBRARY_PATH — gives real file paths that we can
        # open() for DT_NEEDED parsing.  find_library() on Linux only
        # returns a bare soname (not a path), so DT_NEEDED following
        # fails and custom lib dirs (not in ldconfig) are missed.
        for d in os.environ.get('LD_LIBRARY_PATH', '').split(':'):
            if not d:
                continue
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate
        # Fallback: find_library (ldconfig cache).  Returns soname on
        # Linux (usable by dlopen, but not openable as a file path).
        return ct.util.find_library(
            name.replace('lib', '', 1).split('.so')[0])

    def _ensure_loaded(self, name):
        """Recursively preload `name` and its transitive deps.

        Encrypted libs are loaded from memfd with RTLD_GLOBAL.
        Unencrypted libs are followed (to discover encrypted deps behind
        them) and pre-loaded with RTLD_GLOBAL so $ORIGIN RPATH deps
        resolve correctly when consumers load from memfd.
        """
        # Resolve soname → filename (DT_NEEDED uses sonames like
        # "libB.so.1", but fd_map is keyed by filename "libB.so.1.2.3").
        name = self._soname_to_key.get(name, name)
        if name in self._loaded:
            return
        self._loaded.add(name)
        _Real = getattr(ct.CDLL, '_antirev_real', ct.CDLL)

        if name in self._libs:
            # Encrypted lib — load deps first, then load via soname symlink
            # so glibc registers the lib under its soname (not the memfd
            # path), allowing DT_NEEDED resolution to find it.
            fd = self._libs[name]
            deps = _get_needed(fd)
            import sys; print(f"[dbg] ENCRYPTED {name} deps={deps}",
                              file=sys.stderr)
            for dep in deps:
                self._ensure_loaded(dep)
            soname = _get_soname(fd) or name
            link = os.path.join(self._link_dir, soname)
            if not os.path.exists(link):
                os.symlink(f"/proc/self/fd/{fd}", link)
            _Real(link, mode=ct.RTLD_GLOBAL)
        else:
            # Unencrypted dep — follow DT_NEEDED to discover encrypted
            # deps behind it, then pre-load with RTLD_GLOBAL.
            import sys; print(f"[dbg] DISK {name}", file=sys.stderr)
            disk_path = self._resolve_disk(name)
            if disk_path:
                for dep in _get_needed_from_path(disk_path):
                    self._ensure_loaded(dep)
            try:
                _Real(disk_path or name, mode=ct.RTLD_GLOBAL)
            except OSError:
                pass  # system lib already loaded, or linker will find it

    def preload_all(self):
        """Load ALL daemon libs with RTLD_GLOBAL in dependency order.

        Needed when encrypted libs have C constructors that dlopen other
        encrypted libs at init time (constructor dlopens aren't visible
        in DT_NEEDED, so on-demand loading can't discover them).

        For normal DT_NEEDED chains, on-demand loading via patch_ctypes()
        is preferred — it only loads the transitive deps actually needed.
        """
        dep_count = {}
        for name in self._libs:
            dep_count[name] = len(_get_needed(self._libs[name]))
        for name in sorted(self._libs, key=lambda n: (dep_count[n], n)):
            self._ensure_loaded(name)

    def patch_ctypes(self):
        """Monkey-patch ctypes.CDLL for on-demand encrypted lib loading.

        When ctypes.CDLL("libfoo.so") is called, only foo's transitive
        encrypted deps (from DT_NEEDED) are preloaded — not all daemon
        libs.  Unneeded libs like zzz are never touched.
        """
        client = self
        fd_map = self._libs
        soname_map = self._soname_to_key
        _RealCDLL = getattr(ct.CDLL, '_antirev_real', ct.CDLL)

        class _PatchedCDLL(_RealCDLL):
            _antirev_real = _RealCDLL

            def __init__(self, name, *args, **kwargs):
                if name:
                    base = name.rsplit('/', 1)[-1]
                    # Resolve soname → filename if needed
                    key = soname_map.get(base, base)
                    if key in fd_map:
                        client._ensure_loaded(key)
                        soname = _get_soname(fd_map[key]) or key
                        name = os.path.join(client._link_dir, soname)
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


def activate(key_source=None, preload='on_demand'):
    """Connect to daemon and patch ctypes.CDLL for encrypted lib loading.

    Args:
        key_source: path to key file or daemon binary. If None,
                    auto-discovers via ANTIREV_KEY env or .antirev-libd.
        preload: 'on_demand' (default) — load encrypted deps only when
                     ctypes.CDLL() is called, based on DT_NEEDED.
                 'all' — preload ALL daemon libs upfront (needed when
                     encrypted libs have C constructors that dlopen
                     other encrypted libs at init time).

    Returns:
        The AntirevClient instance (for introspection / manual use).
    """
    if key_source is None:
        key_source = _find_key_source()
    client = AntirevClient(key_source)
    if preload == 'all':
        client.preload_all()
    client.patch_ctypes()
    n = len(client._loaded & set(client._libs)) if client._loaded else 0
    mode = f"preloaded {n}" if preload == 'all' else "on-demand"
    print(f"[antirev] {len(client._libs)} libs available ({mode}), "
          f"ctypes.CDLL patched", file=sys.stderr)
    return client
