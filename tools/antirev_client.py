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

Usage (auto-patch — works with both import and ctypes.CDLL):
    from antirev_client import activate

    activate("/path/to/.antirev-libd")  # or key file

    # Python import of encrypted native extensions now works:
    import my_encrypted_module          # redirected to memfd

    # ctypes.CDLL also transparently loads encrypted libs:
    import ctypes
    lib = ctypes.CDLL("libFoo.so")     # redirected to memfd

Key source discovery for activate():
    1. Explicit path argument
    2. ANTIREV_KEY env var (path to key file or daemon binary)
    3. .antirev-libd in the script's directory
"""

import array
import atexit
import ctypes as ct
import ctypes.util
import os
import shutil
import socket
import struct
import sys
import tempfile
from pathlib import Path

KEY_SIZE = 32
SCM_BATCH = 250

# Daemon protocol v2 (matches stub/stub.c OP_*)
OP_INIT    = 0x01
OP_GET_LIB = 0x02
OP_BYE     = 0x03
OP_BATCH   = 0x81
OP_END     = 0x82
OP_LIB     = 0x83


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


# ── Daemon protocol v2 framing ──────────────────────────────────────
#
# Every message on the wire is:
#   [u32 op][u32 plen][payload bytes] (+ optional SCM_RIGHTS ancillary)
#
# Ancillary fds are attached to the first byte of the sendmsg, so a
# single recvmsg for the header picks them up alongside bytes 0..7.

_FD_SIZE = array.array('i').itemsize


def _recv_exact(sd, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sd.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("antirev daemon closed connection")
        buf += chunk
    return bytes(buf)


def _send_msg(sd, op, payload=b""):
    """Send one framed v2 message (no ancillary fds from the client)."""
    hdr = struct.pack('<II', op, len(payload))
    sd.sendall(hdr + payload)


def _recv_msg(sd):
    """Receive one v2 message. Returns (op, payload, fds)."""
    cmsg_len = socket.CMSG_SPACE(SCM_BATCH * _FD_SIZE)
    msg, ancdata, _flags, _addr = sd.recvmsg(8, cmsg_len)
    if not msg:
        raise ConnectionError("antirev daemon closed connection")

    # Ancillary fds ride with the first byte of the message — collect
    # them before doing any follow-up recv() calls.
    fds = []
    for level, type_, cmsg_data in ancdata:
        if level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS:
            arr = array.array('i')
            usable = len(cmsg_data) - (len(cmsg_data) % _FD_SIZE)
            arr.frombytes(cmsg_data[:usable])
            fds.extend(arr.tolist())

    # Stream sockets can short-read; finish the header if needed.
    if len(msg) < 8:
        msg += _recv_exact(sd, 8 - len(msg))

    op, plen = struct.unpack_from('<II', msg, 0)
    payload = _recv_exact(sd, plen) if plen else b""
    return op, payload, fds


def _build_init_payload(filter_names):
    """OP_INIT payload: [u32 nfilter] [(u16 nlen, bytes) * nfilter]."""
    parts = [struct.pack('<I', len(filter_names))]
    for name in filter_names:
        nb = name.encode() if isinstance(name, str) else name
        parts.append(struct.pack('<H', len(nb)))
        parts.append(nb)
    return b"".join(parts)


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
        # PID-tagged prefix matches the C stub's format so the daemon's
        # sweep_dead_symlink_dirs reaper can identify and clean stale
        # dirs from crashed Python processes.  The atexit hook handles
        # the normal-exit case.
        self._link_dir = tempfile.mkdtemp(prefix=f"antirev_{os.getpid()}_")
        atexit.register(self._cleanup_link_dir)
        # Escape hatch, same semantics as dlopen_shim's ANTIREV_NO_PRELOAD:
        # when set, _ensure_loaded / _ensure_deps still materialize the
        # soname symlinks and recurse through the DT_NEEDED chain, but
        # they do NOT call _Real(link, RTLD_GLOBAL) on each dep.  The
        # caller's own ctypes.CDLL() (or Python import) then triggers
        # glibc's normal recursive DT_NEEDED walk against the symlink
        # dir, mapping every dep first and running all ctors together
        # at the end.  Matches plaintext semantics and fixes business
        # libs with implicit inter-lib symbol dependencies (where one
        # lib references a symbol provided by a sibling lib with no
        # DT_NEEDED edge between them — the per-dep RTLD_GLOBAL preload
        # runs each dep's ctors in isolation and crashes on lazy binds
        # across the implicit boundary).
        npe = os.environ.get('ANTIREV_NO_PRELOAD', '')
        self._no_preload = bool(npe) and npe != '0'
        # Prepend symlink dir to LD_LIBRARY_PATH so glibc's DT_NEEDED
        # resolution finds our soname symlinks (→ memfd) before any
        # encrypted copies on disk.
        ld_path = os.environ.get('LD_LIBRARY_PATH', '')
        os.environ['LD_LIBRARY_PATH'] = self._link_dir + (':' + ld_path if ld_path else '')
        self._connect()
        self._build_soname_map()

    def _cleanup_link_dir(self):
        """atexit hook: remove the symlink dir on normal Python exit.

        The fds backing the symlinks are pinned by the kernel mappings
        of the libs we loaded, so removing the symlinks doesn't affect
        any already-loaded module.  Fired LIFO with respect to other
        atexit handlers; AntirevClient is typically constructed early
        so this fires late, after most teardown that might still walk
        the dir."""
        try:
            shutil.rmtree(self._link_dir, ignore_errors=True)
        except Exception:
            pass

    def _connect(self):
        sock_name = _compute_sock_name(self._key)
        sd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sd.connect(b'\x00' + sock_name.encode())
            self._receive_libs(sd)
            try:
                _send_msg(sd, OP_BYE)
            except OSError:
                pass
        finally:
            sd.close()

    def _receive_libs(self, sd: socket.socket):
        """v2 handshake: send OP_INIT (empty filter = full set), then
        read OP_BATCH messages until OP_END, populating self._libs."""
        _send_msg(sd, OP_INIT, _build_init_payload(()))

        while True:
            op, payload, fds = _recv_msg(sd)
            if op == OP_END:
                break
            if op != OP_BATCH:
                raise RuntimeError(
                    f"antirev daemon: unexpected op {op:#x} (expected OP_BATCH)")
            if len(payload) < 4:
                raise RuntimeError("antirev daemon: short OP_BATCH payload")

            nlibs = struct.unpack_from('<I', payload, 0)[0]
            if nlibs != len(fds):
                raise RuntimeError(
                    f"antirev daemon: OP_BATCH lib count {nlibs} "
                    f"!= received fds {len(fds)}")

            off = 4
            for i in range(nlibs):
                if off + 2 > len(payload):
                    raise RuntimeError("antirev daemon: truncated OP_BATCH name")
                nlen = struct.unpack_from('<H', payload, off)[0]
                off += 2
                if off + nlen > len(payload):
                    raise RuntimeError("antirev daemon: truncated OP_BATCH name")
                name = payload[off:off + nlen].decode()
                off += nlen
                self._libs[name] = fds[i]

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

        Used by preload_all() when the caller has explicitly opted in
        to upfront loading of every daemon lib.  For on-demand paths
        (patch_ctypes / patch_import), call _ensure_deps() instead so
        the caller retains its single refcount on the root lib.
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
            for dep in deps:
                self._ensure_loaded(dep)
            soname = _get_soname(fd) or name
            link = os.path.join(self._link_dir, soname)
            if not os.path.exists(link):
                os.symlink("/proc/self/fd/{}".format(fd), link)
            if not self._no_preload:
                try:
                    _Real(link, mode=ct.RTLD_GLOBAL)
                except OSError as e:
                    print("[antirev] warning: failed to preload {}: {}".format(
                        name, e), file=sys.stderr)
        else:
            # Unencrypted dep — follow DT_NEEDED to discover encrypted
            # deps behind it, then pre-load with RTLD_GLOBAL.
            disk_path = self._resolve_disk(name)
            if disk_path:
                for dep in _get_needed_from_path(disk_path):
                    self._ensure_loaded(dep)
            if not self._no_preload:
                try:
                    _Real(disk_path or name, mode=ct.RTLD_GLOBAL)
                except OSError:
                    pass  # system lib already loaded, or linker will find it

    def _ensure_deps(self, name):
        """Preload `name`'s transitive dependency chain — but NOT `name`
        itself — and materialize the soname symlink for `name` so the
        caller can reference it by path.

        Used from patch_ctypes / patch_import for on-demand loading: we
        prep the DT_NEEDED closure so the caller's own dlopen (Python
        import or ctypes.CDLL) finds every dep in glibc's link map,
        but we leave the root lib's refcount to the caller.  That way
        dropping the CDLL handle (or unloading the extension) actually
        brings the root's refcount to zero — which is required for
        plugin systems that cycle plugins carrying overlapping static
        state (e.g. libprotobuf descriptor_pool collisions when two
        plugins have shared .proto files compiled in).
        """
        name = self._soname_to_key.get(name, name)
        if name in self._libs:
            fd = self._libs[name]
            for dep in _get_needed(fd):
                self._ensure_loaded(dep)
            # Ensure the soname symlink exists even though we're not
            # pre-loading the root ourselves — the caller opens it by
            # this path.
            soname = _get_soname(fd) or name
            link = os.path.join(self._link_dir, soname)
            if not os.path.exists(link):
                os.symlink("/proc/self/fd/{}".format(fd), link)
        else:
            disk_path = self._resolve_disk(name)
            if disk_path:
                for dep in _get_needed_from_path(disk_path):
                    self._ensure_loaded(dep)

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

    def patch_import(self):
        """Install sys.meta_path hook for encrypted Python extension modules.

        Intercepts ``import`` of native .so extensions that are encrypted
        on disk, loading them from the daemon's memfd instead.  Also
        walks the transitive DT_NEEDED chain of *non*-encrypted extensions
        (including through unencrypted intermediaries) and preloads only
        the encrypted deps that each specific import actually needs.
        This matches stub.c's selective LD_PRELOAD approach and avoids
        conflicts from loading unrelated libs globally.
        """
        import importlib.abc
        import importlib.machinery
        import importlib.util

        client = self
        MAGIC = b"ANTREV01"
        ext_suffixes = importlib.machinery.EXTENSION_SUFFIXES

        class _Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                tail = fullname.rsplit('.', 1)[-1]
                search = list(path) if path else sys.path

                for suffix in ext_suffixes:
                    fname = tail + suffix
                    for d in search:
                        if not isinstance(d, str):
                            continue
                        fpath = os.path.join(d, fname)
                        if not os.path.isfile(fpath):
                            continue
                        try:
                            with open(fpath, 'rb') as f:
                                hdr = f.read(8)
                        except OSError:
                            continue

                        if hdr == MAGIC:
                            # Encrypted extension — redirect to memfd.
                            # Preload deps only; Python's import will be
                            # the single owner of the root's refcount so
                            # module unload semantics stay intact.
                            base = os.path.basename(fpath)
                            key = client._soname_to_key.get(base, base)
                            if key not in client._libs:
                                return None
                            client._ensure_deps(key)
                            fd = client._libs[key]
                            memfd = "/proc/self/fd/{}".format(fd)
                            loader = importlib.machinery.ExtensionFileLoader(
                                fullname, memfd)
                            return importlib.util.spec_from_file_location(
                                fullname, memfd, loader=loader)

                        if hdr[:4] == b'\x7fELF':
                            # Non-encrypted extension — preload encrypted
                            # libs in its transitive DT_NEEDED chain so
                            # ld.so finds them when it dlopen's this file.
                            # _ensure_loaded follows unencrypted intermediaries
                            # too, so ext→unenc→enc chains are covered.
                            for dep in _get_needed_from_path(fpath):
                                client._ensure_loaded(dep)
                        return None  # let normal import handle it
                return None

        sys.meta_path.insert(0, _Finder())

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
                        # Preload the DT_NEEDED closure only; let
                        # super().__init__ below take the single
                        # refcount on the root lib so dlclose can
                        # actually unload it.
                        client._ensure_deps(key)
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
    """Connect to daemon and transparently load encrypted libs.

    Patches both Python's ``import`` (for encrypted native extensions)
    and ``ctypes.CDLL`` (for explicit ctypes loading).  The import hook
    automatically preloads only the transitive encrypted deps of each
    extension as it is imported — matching stub.c's approach of only
    preloading what each binary actually needs.

    Args:
        key_source: path to key file or daemon binary. If None,
                    auto-discovers via ANTIREV_KEY env or .antirev-libd.
        preload: 'on_demand' (default) — load encrypted deps only when
                     an import or ctypes.CDLL() actually needs them.
                     Avoids conflicts from loading unrelated libs (e.g.
                     protobuf descriptor collisions between two gRPC
                     .so files that are never used together).
                 'all' — preload ALL daemon libs upfront.  Use only
                     when encrypted libs have C constructors that
                     dlopen other encrypted libs at init time.

    Environment:
        ANTIREV_NO_PRELOAD=1 — escape hatch.  When set, disables the
            per-dep RTLD_GLOBAL preload that _ensure_loaded /
            _ensure_deps normally does; soname symlinks are still
            materialized and the DT_NEEDED chain is still walked, but
            no _Real(link, RTLD_GLOBAL) call is issued per dep.  The
            caller's own ctypes.CDLL() / Python import then triggers
            glibc's natural recursive DT_NEEDED load, matching
            plaintext semantics.  Required for business libs with
            implicit inter-lib symbol dependencies (one lib references
            a symbol provided by a sibling lib with no DT_NEEDED edge
            between them).  See stub/dlopen_shim.c for the C-side
            equivalent; the env var is the same name and has the same
            semantics.  The correct long-term fix is to add the
            missing DT_NEEDED edge to the business build.

    Returns:
        The AntirevClient instance (for introspection / manual use).
    """
    if key_source is None:
        key_source = _find_key_source()
    client = AntirevClient(key_source)
    if preload == 'all':
        client.preload_all()
    client.patch_import()
    client.patch_ctypes()
    n = len(client._loaded & set(client._libs)) if client._loaded else 0
    if client._no_preload:
        mode = "no-preload (natural load)"
    elif preload == 'all':
        mode = "preloaded {}".format(n)
    else:
        mode = "on-demand"
    print("[antirev] {} libs available ({}), "
          "import + ctypes.CDLL patched".format(len(client._libs), mode),
          file=sys.stderr)
    return client
