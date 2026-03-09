import os
import ctypes


_lib_path = os.path.abspath("./libmodule_lwe.so")
if not os.path.exists(_lib_path):
    raise FileNotFoundError(f"Missing shared library: {_lib_path}")

_lib = ctypes.CDLL(_lib_path)

_u8_p = ctypes.POINTER(ctypes.c_uint8)

# ------------------------------------------------------------------
# Bridge signatures
# ------------------------------------------------------------------

_lib.bridge_init.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_int]
_lib.bridge_init.restype = ctypes.c_void_p

_lib.bridge_free_engine.argtypes = [ctypes.c_void_p]
_lib.bridge_free_engine.restype = None

_lib.bridge_keygen.argtypes = [ctypes.c_void_p, _u8_p, _u8_p]
_lib.bridge_keygen.restype = ctypes.c_int

_lib.bridge_encrypt.argtypes = [ctypes.c_void_p, _u8_p, ctypes.c_size_t, _u8_p]
_lib.bridge_encrypt.restype = ctypes.c_void_p

_lib.bridge_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, _u8_p, ctypes.c_size_t]
_lib.bridge_decrypt.restype = ctypes.c_int

_lib.bridge_free_ct.argtypes = [ctypes.c_void_p]
_lib.bridge_free_ct.restype = None


class ModuleLWE:
    def __init__(self, k=2, log2q=6, eta=2):
        self._engine = _lib.bridge_init(k, log2q, eta)
        if not self._engine:
            raise RuntimeError("bridge_init failed")

        self._ct = None
        self._has_keypair = False
        self._closed = False

    def keygen(self):
        self._ensure_open()

        seedA = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))
        seedS = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))

        rc = _lib.bridge_keygen(self._engine, seedA, seedS)
        if rc != 0:
            raise RuntimeError(f"bridge_keygen failed with code {rc}")

        self._has_keypair = True

    def encrypt(self, msg_bytes: bytes, msg_bitlen: int):
        self._ensure_open()

        if not self._has_keypair:
            raise RuntimeError("keygen must be called before encrypt")

        expected_len = (msg_bitlen + 7) // 8
        if len(msg_bytes) != expected_len:
            raise ValueError(
                f"msg_bytes length must be {expected_len} for {msg_bitlen} bits"
            )

        if self._ct:
            _lib.bridge_free_ct(self._ct)
            self._ct = None

        msg_arr = (ctypes.c_uint8 * len(msg_bytes)).from_buffer_copy(msg_bytes)
        seedE = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))

        ct_ptr = _lib.bridge_encrypt(self._engine, msg_arr, msg_bitlen, seedE)
        if not ct_ptr:
            raise RuntimeError("bridge_encrypt failed")

        self._ct = ct_ptr

    def decrypt(self, msg_bitlen: int) -> bytes:
        self._ensure_open()

        if not self._ct:
            raise RuntimeError("no ciphertext available; call encrypt first")

        out_len = (msg_bitlen + 7) // 8
        out_buf = (ctypes.c_uint8 * out_len)()

        rc = _lib.bridge_decrypt(self._engine, self._ct, out_buf, msg_bitlen)
        if rc != 0:
            raise RuntimeError(f"bridge_decrypt failed with code {rc}")

        return bytes(out_buf)

    def free_ciphertext(self):
        if self._ct:
            _lib.bridge_free_ct(self._ct)
            self._ct = None

    def close(self):
        if self._closed:
            return

        self.free_ciphertext()

        if self._engine:
            _lib.bridge_free_engine(self._engine)
            self._engine = None

        self._has_keypair = False
        self._closed = True

    def _ensure_open(self):
        if self._closed or not self._engine:
            raise RuntimeError("ModuleLWE instance is closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass