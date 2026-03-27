

# OpenSSL RSA-3072 PKE Benchmark

This directory evaluates RSA-3072 as the "Traditional Integer-based" PKE baseline.

## Purpose

RSA-3072 is included to represent the standard pre-quantum encryption used in legacy systems. By using the `EVP_PKEY` API with OAEP padding, we establish a baseline for **Pure Public Key Encryption** that is semantically consistent with our Module-LWE based PKE.

## Benchmark Target

- **Library**: `OpenSSL` (v3.0+)
- **Scheme**: `RSA-3072`
- **Padding**: `OAEP` (Optimal Asymmetric Encryption Padding)
- **Security Level**: 128-bit (Equivalent to Kyber512)

## Files

- `bench_rsa.c`: Unified C driver with memory-safe RSA keygen and encryption loops.
- `Makefile`: Automated build script linking `libssl` and `libcrypto`.
- `results/openssl_rsa3072.txt`: Benchmark execution logs.

## Requirements

```bash
sudo apt-get install libssl-dev
```

## Reproducibility (How to Run)

```Bash
cd openssl_rsa3072
make clean
make bench
```

Note: RSA Key Generation is computationally expensive; the benchmark may take several minutes to complete 1000 iterations.

## Benchmark Configuration

Payload Size: 256 bits (32 bytes)

Compiler: GCC -O3 -march=native

Methodology: 50 warmups followed by 1000 fixed-trial iterations.