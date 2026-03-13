import os
import ctypes

_lib_path = os.path.abspath("./libmodule_lwe.so")
if not os.path.exists(_lib_path):
    raise FileNotFoundError(f"Missing shared library: {_lib_path}")

_lib = ctypes.CDLL(_lib_path)
_u8_p = ctypes.POINTER(ctypes.c_uint8)

_lib.bridge_init.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_int]
_lib.bridge_init.restype = ctypes.c_void_p
_lib.bridge_free_engine.argtypes = [ctypes.c_void_p]
_lib.bridge_keygen.argtypes = [ctypes.c_void_p, _u8_p, _u8_p]
_lib.bridge_encrypt.argtypes = [ctypes.c_void_p, _u8_p, ctypes.c_size_t, _u8_p]
_lib.bridge_encrypt.restype = ctypes.c_void_p
_lib.bridge_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, _u8_p, ctypes.c_size_t]
_lib.bridge_free_ct.argtypes = [ctypes.c_void_p]

class ModuleLWE:
    def __init__(self, k: int = 2, log2q: int = 32, eta: int = 2):
        self._engine = _lib.bridge_init(k, log2q, eta)
        if not self._engine: raise RuntimeError("bridge_init failed")
        self._has_keypair = False
        self._cts = []
        self._closed = False
        self._msg_bitlen = 0

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()

    def keygen(self):
        self._ensure_open()
        seedA = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))
        seedS = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))
        if _lib.bridge_keygen(self._engine, seedA, seedS) != 0:
            raise RuntimeError("bridge_keygen failed")
        self._has_keypair = True

    def encrypt(self, msg_bytes: bytes, msg_bitlen: int):
        self._ensure_open()
        if not self._has_keypair: raise RuntimeError("Call keygen() first")
        self.free_ciphertext()
        self._msg_bitlen = msg_bitlen
        
        chunk_size = 8 
        blocks = [msg_bytes[i:i+chunk_size] for i in range(0, len(msg_bytes), chunk_size)]
        
        for block in blocks:
            padded = block.ljust(chunk_size, b"\x00")
            msg_arr = (ctypes.c_uint8 * chunk_size).from_buffer_copy(padded)
            seedE = (ctypes.c_uint8 * 32).from_buffer_copy(os.urandom(32))
            
            ct_ptr = _lib.bridge_encrypt(self._engine, msg_arr, 64, seedE)
            if not ct_ptr: raise RuntimeError("bridge_encrypt failed")
            self._cts.append(ct_ptr)

    def decrypt(self, msg_bitlen: int = None) -> bytes:
        self._ensure_open()
        if not self._cts: raise RuntimeError("no ciphertext available")
        if msg_bitlen is None: msg_bitlen = self._msg_bitlen

        recovered = b""
        for ct_ptr in self._cts:
            out_buf = (ctypes.c_uint8 * 8)()
            if _lib.bridge_decrypt(self._engine, ct_ptr, out_buf, 64) != 0:
                raise RuntimeError("bridge_decrypt failed")
            recovered += bytes(out_buf)

        target_len = (msg_bitlen + 7) // 8
        return recovered[:target_len]

    def free_ciphertext(self):
        for ct_ptr in self._cts: _lib.bridge_free_ct(ct_ptr)
        self._cts = []

    def close(self):
        if self._closed: return
        self.free_ciphertext()
        if self._engine: _lib.bridge_free_engine(self._engine)
        self._closed = True

    def _ensure_open(self):
        if self._closed or not self._engine: raise RuntimeError("Engine closed")
