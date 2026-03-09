import os
import ctypes

lib_path = os.path.abspath("./libmodule_lwe.so")
if not os.path.exists(lib_path):
    raise FileNotFoundError(f"Missing shared library: {lib_path}")

_lib = ctypes.CDLL(lib_path)

_lib.bridge_init.restype = ctypes.c_void_p
_lib.bridge_encrypt.restype = ctypes.c_void_p

class ModuleLWE:
    def __init__(self, k=2, log2q=6, eta=2):
        self.engine_ptr = _lib.bridge_init(k, log2q, eta)
        self.ct_ptr = None

    def keygen(self):
        seedA = (ctypes.c_uint8 * 32)(*os.urandom(32))
        seedS = (ctypes.c_uint8 * 32)(*os.urandom(32))
        _lib.bridge_keygen(self.engine_ptr, seedA, seedS)

    def encrypt(self, msg_bytes, msg_bitlen):
        msg_arr = (ctypes.c_uint8 * len(msg_bytes))(*msg_bytes)
        seedE = (ctypes.c_uint8 * 32)(*os.urandom(32))
        self.ct_ptr = _lib.bridge_encrypt(self.engine_ptr, msg_arr, msg_bitlen, seedE)

    def decrypt(self, msg_bitlen):
        byte_len = (msg_bitlen + 7) // 8
        out_buf = (ctypes.c_uint8 * byte_len)()
        _lib.bridge_decrypt(self.engine_ptr, self.ct_ptr, out_buf, msg_bitlen)
        return bytes(out_buf)

    def free_memory(self):
        _lib.bridge_free(self.engine_ptr, self.ct_ptr)