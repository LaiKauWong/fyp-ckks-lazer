# Module-LWE Public Key Encryption Scheme

## Overview
This is a standalone, reusable C module implementing a Public-Key Encryption (PKE) scheme based on the Module-Learning with Errors (Module-LWE) problem. The scheme is built strictly on top of the `lazer` cryptography library's algebra layer primitives (polynomials, vectors, matrices, and samplers), serving as a transparent scheme-layer implementation.

## Lifecycle & Usage
The lifecycle of this module follows standard cryptographic C-library conventions:
1. **Context Initialization**: `lwe_pke_ctx_init()` defines the ring assumptions, module rank ($k$), and noise parameters ($\eta$).
2. **Allocation**: Memory for keys and ciphertexts must be explicitly allocated via `lwe_pke_pk_alloc()`, `sk_alloc()`, and `ct_alloc()`.
3. **Operations**: Call `lwe_pke_keygen()`, `lwe_pke_encrypt()`, and `lwe_pke_decrypt()`.
4. **Deallocation**: Prevent memory leaks by freeing objects with their respective `_free()` functions.

## Message Length & Encoding Assumptions
- **Encoding Strategy**: The current encoding scheme maps 1 message bit to 1 polynomial coefficient (mapping `1` to $\lfloor q/2 \rfloor$ and `0` to $0$).
- **Maximum Capacity**: The maximum supported bit-length of a single message is strictly limited by the **Ring Degree ($n$)** of the configured Lazer polynomial ring.
- **Tested Lengths**: With the current demo ring parameters, robust tests and benchmarks have been explicitly verified for short messages of **32 bits** and **64 bits**.

## How to Compile and Benchmark
This module depends on the `lazer` library, `gmp`, and `mpfr`. Execute the following commands in your bash environment to run the multi-length speed benchmark:

```bash
# Compile objects
gcc -c src/public_key_encryption/module_lwe_pke.c -I. -Ipython/demo
gcc -c src/public_key_encryption/module_lwe_pke_bench.c -I. -Ipython/demo

# Link and build the benchmark executable
g++ module_lwe_pke.o module_lwe_pke_bench.o -L. -llazer ./third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lm -o lwe_bench

# Run the benchmark
LD_LIBRARY_PATH=. ./lwe_bench

## How to use (Makefile targets)
Run these commands from the repository root.

1. Build the base `lazer` library:

make

2. Build the PKE module and its tools:

make -f Makefile.pke


3. Run the test suite:

make -f Makefile.pke test
./lwe_test


4. Run the benchmark:

make -f Makefile.pke bench
./bench_pke

5. Run the Python demos:

make -f Makefile.pke demo
make -f Makefile.pke input
make -f Makefile.pke sentence

6. Clean PKE build artifacts:

make -f Makefile.pke clean



