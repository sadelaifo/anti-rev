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

    def patch_ctypes(self):
        """Monkey-patch ctypes.CDLL to transparently load encrypted libs.

        After calling this, any ctypes.CDLL("libFoo.so") where libFoo.so
        is served by the daemon will be redirected to the decrypted memfd.
        """
        fd_map = self._libs
        # Save the real CDLL before we replace it — used by the
        # patched class as its base so we never double-intercept.
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
    client.patch_ctypes()
    print(f"[antirev] patched ctypes.CDLL ({len(client._libs)} libs)",
          file=sys.stderr)
    return client
