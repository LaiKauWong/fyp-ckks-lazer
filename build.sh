#!/bin/bash
set -e

echo "Step 1: Cleaning up historical compilation files..."
rm -f *.o libmodule_lwe.so bench_pke demo_native.py
find . -name "demo_params*.h" -delete
find . -name "demo_params*.py" -delete

echo "Step 2: Generating the official 64-degree secure parameters..."
mkdir -p python/demo
cat << 'EOF' > python/demo/demo_params.py
from math import sqrt
vname = "param"
deg   = 64
mod   = 2**32 - 4607
dim   = (4,8)
wpart = [ list(range(0,8)) ]
wl2   = [ sqrt(2048) ]
wbin  = [ 0 ]
wrej  = [ 0 ]
wlinf = 1
EOF

echo -n "        [Running SageMath Engine] "
sudo docker run --rm -v $(pwd):/app -w /app/scripts sagemath/sagemath:latest sage lin-codegen.sage ../python/demo/demo_params.py > python/demo/demo_params.h 2>/dev/null &
PID=$!
while kill -0 $PID 2>/dev/null; do
    printf "▓"
    sleep 0.5
done
echo " [DONE]"

echo "Step 3: Rewriting C benchmark to support multi-block chunking for large payloads..."
cat << 'EOF' > src/public_key_encryption/module_lwe_pke_bench.c
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

#define NTRIALS 1000
#define WARMUP_TRIALS 50
#define LWE_K 2
#define LOG2Q 32
#define ETA 2

static void randbytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static double diff_ms(struct timespec a, struct timespec b) {
    double sec = (double)(b.tv_sec - a.tv_sec);
    double nsec = (double)(b.tv_nsec - a.tv_nsec);
    return sec * 1000.0 + nsec / 1e6;
}

int main(void) {
    srand((unsigned)time(NULL));
    lazer_init();

    lwe_pke_ctx_t ctx;
    lwe_pke_pk_t pk;
    lwe_pke_sk_t sk;

    if (lwe_pke_ctx_init(ctx, &_param_ring, LWE_K, LOG2Q, ETA) != 0) return 1;
    if (lwe_pke_pk_alloc(pk, ctx) != 0 || lwe_pke_sk_alloc(sk, ctx) != 0) return 1;

    uint8_t seedA[32], seedS[32];
    randbytes(seedA, 32); 
    randbytes(seedS, 32);
    if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) return 1;

    printf("=================================================================\n");
    printf("Module-LWE PKE Benchmark (Multi-Length Transparent Chunking)\n");
    printf("=================================================================\n");
    printf("Ring source           : demo_params.h\n");
    printf("Module rank (k)       : %d\n", LWE_K);
    printf("log2(q)               : %d\n", LOG2Q);
    printf("Noise parameter (eta) : %d\n", ETA);
    printf("Benchmark trials      : %d\n", NTRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=================================================================\n\n");
    printf("Msg Size   | Success Rate | KeyGen (ms)  | Encrypt (ms) | Decrypt (ms)\n");
    printf("---------------------------------------------------------------------------------\n");

    const size_t test_bitlens[] = {32, 64, 128, 256, 512, 1024};
    size_t ntests = sizeof(test_bitlens) / sizeof(test_bitlens[0]);

    for (size_t ti = 0; ti < ntests; ti++) {
        size_t bitlen = test_bitlens[ti];
        size_t bytelen = (bitlen + 7) / 8;
        size_t chunk_size = 8;
        size_t num_chunks = (bytelen + chunk_size - 1) / chunk_size;

        double t_keygen_ms = 0.0, t_encrypt_ms = 0.0, t_decrypt_ms = 0.0;
        int completed_trials = 0;
        struct timespec ts1, ts2;

        for (int trial = 0; trial < NTRIALS + WARMUP_TRIALS; trial++) {
            // Fix: Add explicit casts for C++ compilation
            uint8_t *msg = (uint8_t *)calloc(1, bytelen);
            uint8_t *dec = (uint8_t *)calloc(1, bytelen);
            randbytes(msg, bytelen);

            randbytes(seedA, 32); 
            randbytes(seedS, 32);
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            int rc_kg = lwe_pke_keygen(ctx, pk, sk, seedA, seedS);
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (rc_kg != 0) { free(msg); free(dec); continue; }
            if (trial >= WARMUP_TRIALS) t_keygen_ms += diff_ms(ts1, ts2);

            // Fix: Add explicit cast for C++ compilation
            lwe_pke_ct_struct *cts = (lwe_pke_ct_struct *)calloc(num_chunks, sizeof(lwe_pke_ct_struct));
            for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_alloc(&cts[c], ctx);

            int enc_ok = 1;
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            for(size_t c = 0; c < num_chunks; c++) {
                uint8_t seedE[32]; randbytes(seedE, 32);
                uint8_t chunk_buf[8] = {0};
                size_t copy_len = (bytelen - c*8 > 8) ? 8 : (bytelen - c*8);
                memcpy(chunk_buf, msg + c*8, copy_len);
                if (lwe_pke_encrypt(ctx, &cts[c], pk, chunk_buf, 64, seedE) != 0) enc_ok = 0;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (!enc_ok) { 
                for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_free(&cts[c]); 
                free(cts); free(msg); free(dec); continue; 
            }
            if (trial >= WARMUP_TRIALS) t_encrypt_ms += diff_ms(ts1, ts2);

            int dec_ok = 1;
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            for(size_t c = 0; c < num_chunks; c++) {
                uint8_t chunk_buf[8] = {0};
                if (lwe_pke_decrypt(ctx, chunk_buf, 64, &cts[c], sk) != 0) dec_ok = 0;
                size_t copy_len = (bytelen - c*8 > 8) ? 8 : (bytelen - c*8);
                memcpy(dec + c*8, chunk_buf, copy_len);
            }
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (trial >= WARMUP_TRIALS) t_decrypt_ms += diff_ms(ts1, ts2);

            if (dec_ok && memcmp(msg, dec, bytelen) == 0) {
                if (trial >= WARMUP_TRIALS) completed_trials++;
            }

            for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_free(&cts[c]);
            free(cts); free(msg); free(dec);
        }

        if (completed_trials > 0) {
            double avg_kg = t_keygen_ms / completed_trials;
            double avg_enc = t_encrypt_ms / completed_trials;
            double avg_dec = t_decrypt_ms / completed_trials;
            double success_rate = 100.0 * completed_trials / NTRIALS;
            printf("%4zu bits | %6.2f %% | %10.4f   | %10.4f   | %10.4f   \n",
                   bitlen, success_rate, avg_kg, avg_enc, avg_dec);
        } else {
            printf("%4zu bits |   0.00 %% |        N/A   |        N/A   |        N/A   \n", bitlen);
        }
    }
    printf("=================================================================\n");

    lwe_pke_pk_free(pk);
    lwe_pke_sk_free(sk);
    return 0;
}
EOF

echo "Step 4: Fixing include paths and ring variables in remaining C sources..."
sed -i 's|../../python/demo/demo_params.h|demo_params.h|g' src/public_key_encryption/*.c
sed -i 's/demo_params_256\.h/demo_params.h/g' src/public_key_encryption/*.c
sed -i 's/&_my_param_ring/\&_param_ring/g' src/public_key_encryption/*.c
sed -i 's/&_ring256_ring/\&_param_ring/g' src/public_key_encryption/*.c

echo "Step 5: Compiling the underlying C engine and bridge with HEXL acceleration..."
gcc -fPIC -O3 -DLAZER_HEXL -c src/public_key_encryption/module_lwe_pke.c -I. -Ipython/demo
gcc -fPIC -O3 -DLAZER_HEXL -c src/public_key_encryption/bridge_module_lwe_pke.c -I. -Ipython/demo

g++ -shared module_lwe_pke.o bridge_module_lwe_pke.o \
    -L. -llazer -Wl,-rpath='.' \
    ./third_party/hexl-development/build/hexl/lib/libhexl.a \
    -lmpfr -lgmp -lm -o libmodule_lwe.so

echo "Step 6: Compiling the C benchmark program..."
g++ -O3 -DLAZER_HEXL -DLOG2Q=32 src/public_key_encryption/module_lwe_pke_bench.c module_lwe_pke.o \
    -I. -Ipython/demo -L. -llazer -Wl,-rpath='.' \
    ./third_party/hexl-development/build/hexl/lib/libhexl.a \
    -lmpfr -lgmp -lm -o bench_pke

echo "Step 7: Generating Python wrapper with transparent chunking (module_lwe_pke.py)..."
cat << 'EOF' > python/public_key_encryption/module_lwe_pke.py
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
EOF

echo "Step 8: Generating detailed Python test script (demo_native.py)..."
cat << 'EOF' > demo_native.py
import os
import sys
sys.path.append('python/public_key_encryption')
from module_lwe_pke import ModuleLWE

def main():
    with ModuleLWE(k=2, log2q=32, eta=2) as pke:
        pke.keygen()
        print("\nNative LWE Engine: High-Capacity Transparent Chunking Test Initiated!")
        print("=" * 65)
        
        for b in [64, 128, 256, 1024]:
            byte_len = b // 8
            msg = os.urandom(byte_len)
            
            print(f"[*] Testing {b}-bit ({byte_len} bytes) Payload...")
            
            pke.encrypt(msg, b)
            dec = pke.decrypt(b)
            
            chunk_size = 8
            chunk_count = (byte_len + chunk_size - 1) // chunk_size
            
            msg_hex = msg.hex()
            dec_hex = dec.hex()
            preview_len = 32
            msg_preview = msg_hex[:preview_len] + ("..." if len(msg_hex) > preview_len else "")
            dec_preview = dec_hex[:preview_len] + ("..." if len(dec_hex) > preview_len else "")

            print(f"    - Hardware Chunks  : {chunk_count} block(s)")
            print(f"    - Original Data    : {msg_preview}")
            print(f"    - Decrypted Data   : {dec_preview}")
            print(f"    - Validation       : {'SUCCESS (Match: True)' if msg == dec else 'FAILED'}")
            print("-" * 65)

if __name__ == "__main__":
    main()
EOF

echo -e "\n================================================================="
echo "Executing Python Arbitrary Length Chunking Test"
echo "================================================================="
python3 demo_native.py

echo -e "\n================================================================="
echo "Executing C Native Microsecond Benchmark"
echo "================================================================="
./bench_pke