# Module-LWE Public Key Encryption

## Overview

This directory contains a prototype public-key encryption (PKE) implementation based on the Module-LWE assumption, built on top of the LaZer algebra layer.

The implementation is intended as a transparent scheme-layer module rather than a replacement for LaZer's native functionality. It reuses LaZer's polynomial-ring infrastructure, polynomial/vector/matrix types, and sampling primitives to realize a simple Module-LWE encryption workflow in C, together with a C test program, a benchmark, a C bridge layer, and Python wrappers.

At the current stage, this module should be understood as a research prototype for experimentation and integration work, not as a production-ready cryptosystem.

---

## Directory Contents

This directory currently contains the following main components:

- `module_lwe_pke.h` / `module_lwe_pke.c`  
  Core Module-LWE PKE implementation.

- `bridge_module_lwe_pke.h` / `bridge_module_lwe_pke.c`  
  Bridge layer used by the Python wrapper.

- `module_lwe_pke_test.c`  
  Single-block correctness test.

- `module_lwe_pke_bench.c`  
  Benchmark for end-to-end encryption and decryption.

In addition, Python-side wrappers and demos are placed under:

- `python/public_key_encryption/`

---

## Design Summary

The current implementation follows a basic Module-LWE encryption structure with:

- context initialization over a LaZer polynomial ring
- explicit allocation and deallocation of keys and ciphertexts
- randomized key generation
- bitwise plaintext encoding into a polynomial
- encryption and decryption over the configured ring/module parameters

The implementation currently uses a simple binary plaintext embedding:

- plaintext bit `0` is encoded as coefficient `0`
- plaintext bit `1` is encoded as coefficient `⌊q/2⌋`

This is a straightforward bit-oriented encoding suitable for a simple PKE prototype.

---

## Message Encoding and Capacity

### Single-block encoding

The current encoder maps **one message bit to one polynomial coefficient**.

Therefore, the maximum plaintext size for a **single ciphertext block** is bounded by the number of coefficients in the message polynomial, i.e. by the effective ring degree of the configured LaZer ring.

In other words:

- `single-block payload capacity = number of polynomial coefficients`
- with the current demo ring parameters, this is typically `64 bits`

### Multi-block chunking

For longer messages, the Python wrapper and benchmark use a **multi-block chunking** strategy:

- the plaintext is split into fixed-capacity blocks
- each block is encrypted independently
- decryption recovers each block and concatenates the results

So support for lengths such as `128`, `256`, or `512` bits should be interpreted as **multi-block message handling on top of a fixed-capacity primitive**, not as a single native ciphertext carrying all those bits at once.

---

## Lifecycle and API Usage

The C module follows a conventional cryptographic object lifecycle:

1. **Initialize context**  
   `lwe_pke_ctx_init()` sets the ring, module rank `k`, modulus-related settings, and noise parameter `eta`.

2. **Allocate objects**  
   Use:
   - `lwe_pke_pk_alloc()`
   - `lwe_pke_sk_alloc()`
   - `lwe_pke_ct_alloc()`

3. **Run cryptographic operations**  
   Use:
   - `lwe_pke_keygen()`
   - `lwe_pke_encrypt()`
   - `lwe_pke_decrypt()`

4. **Free allocated objects**  
   Use the corresponding `_free()` functions to avoid leaks.

---

## Current Status

At the moment, the implementation provides:

- a working Module-LWE PKE prototype in C
- single-block correctness testing
- benchmark code for chunked multi-block messages
- a Python wrapper via a C bridge layer
- simple demo scripts for experimenting with byte-string encryption

This implementation is useful for:

- understanding how a scheme layer can be built on top of LaZer's algebra layer
- experimenting with plaintext encoding and ciphertext flow
- testing modular integration before more advanced work such as RLWE/CKKS-oriented extensions

---

## Build Requirements

This module depends on:

- the base `lazer` library
- `gmp`
- `mpfr`
- the HEXL static library used in the current build flow

The base LaZer library should be built first from the repository root.

---

## Recommended Build Flow
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



