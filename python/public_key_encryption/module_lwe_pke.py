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

# NEW: query payload capacity from bridge
_lib.bridge_msg_capacity_bits.argtypes = [ctypes.c_void_p]
_lib.bridge_msg_capacity_bits.restype = ctypes.c_size_t

_lib.bridge_msg_capacity_bytes.argtypes = [ctypes.c_void_p]
_lib.bridge_msg_capacity_bytes.restype = ctypes.c_size_t


class ModuleLWE:
    def __init__(self, k: int = 2, log2q: int = 32, eta: int = 2):
        self._engine = _lib.bridge_init(k, log2q, eta)
        if not self._engine:
            raise RuntimeError("bridge_init failed")

        self._cts = []
        self._has_keypair = False
        self._closed = False
        self._msg_bitlen = 0

        self._block_bits = _lib.bridge_msg_capacity_bits(self._engine)
        self._block_bytes = _lib.bridge_msg_capacity_bytes(self._engine)

        if self._block_bits == 0 or self._block_bytes == 0:
            _lib.bridge_free_engine(self._engine)
            self._engine = None
            raise RuntimeError("failed to query message capacity from bridge")

    @property
    def block_bits(self) -> int:
        return int(self._block_bits)

    @property
    def block_bytes(self) -> int:
        return int(self._block_bytes)

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

        if msg_bitlen < 0:
            raise ValueError("msg_bitlen must be non-negative")

        expected_len = (msg_bitlen + 7) // 8
        if len(msg_bytes) != expected_len:
            raise ValueError(
                f"msg_bytes length must be {expected_len} for {msg_bitlen} bits"
            )

        self.free_ciphertext()
        self._msg_bitlen = msg_bitlen

        if msg_bitlen == 0:
            return

        for offset in range(0, len(msg_bytes), self._block_bytes):
            block = msg_bytes[offset : offset + self._block_bytes]
            padded = block.ljust(self._block_bytes, b"\x00")

            msg_arr = (ctypes.c_uint8 * self._block_bytes).from_buffer_copy(padded)
            seedE = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))

            chunk_index = offset // self._block_bytes
            remaining_bits = msg_bitlen - chunk_index * self._block_bits
            chunk_bits = self._block_bits if remaining_bits > self._block_bits else remaining_bits

            if chunk_bits <= 0 or chunk_bits > self._block_bits:
                self.free_ciphertext()
                raise RuntimeError(f"invalid chunk_bits={chunk_bits}")

            ct_ptr = _lib.bridge_encrypt(self._engine, msg_arr, chunk_bits, seedE)
            if not ct_ptr:
                self.free_ciphertext()
                raise RuntimeError("bridge_encrypt failed")

            self._cts.append(ct_ptr)

    def decrypt(self, msg_bitlen: int | None = None) -> bytes:
        self._ensure_open()

        if msg_bitlen is None:
            msg_bitlen = self._msg_bitlen

        if msg_bitlen < 0:
            raise ValueError("msg_bitlen must be non-negative")

        if msg_bitlen == 0:
            return b""

        if not self._cts:
            raise RuntimeError("no ciphertext available; call encrypt first")

        recovered = bytearray()

        for idx, ct_ptr in enumerate(self._cts):
            out_buf = (ctypes.c_uint8 * self._block_bytes)()

            remaining_bits = msg_bitlen - idx * self._block_bits
            chunk_bits = self._block_bits if remaining_bits > self._block_bits else remaining_bits

            if chunk_bits <= 0 or chunk_bits > self._block_bits:
                raise RuntimeError(f"invalid chunk_bits={chunk_bits}")

            rc = _lib.bridge_decrypt(self._engine, ct_ptr, out_buf, chunk_bits)
            if rc != 0:
                raise RuntimeError(f"bridge_decrypt failed with code {rc}")

            recovered.extend(bytes(out_buf))

        out_len = (msg_bitlen + 7) // 8
        return bytes(recovered[:out_len])

    def free_ciphertext(self):
        for ct_ptr in self._cts:
            if ct_ptr:
                _lib.bridge_free_ct(ct_ptr)
        self._cts = []

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