# OpenSSL SM2 Public Key Encryption Benchmark

This directory contains a performance evaluation of the **SM2** public key cryptography algorithm, specifically focusing on its **Public Key Encryption (PKE)** functionality as defined in the Chinese National Standard (GB/T 32907-2016).

## Purpose

The SM2 benchmark serves as a "Modern Elliptic Curve" baseline. Unlike many ECC-based schemes that are limited to Key Exchange (ECDH), SM2 provides a native, standardized PKE mode. This allows for a mathematically "clean" comparison with our LAZER-based PKE, as both systems perform direct encryption and decryption of 256-bit messages without requiring KEM-to-PKE conversions.

## Benchmark Target

- **Implementation**: OpenSSL 3.x EVP API
- **Algorithm**: SM2 (Elliptic Curve Cryptography)
- **Security Strength**: ~128-bit (equivalent to NIST P-256)
- **Mode**: Native PKE (Public Key Encryption)

## Files

- `bench_sm2.c`: C-based driver for high-precision timing using `CLOCK_MONOTONIC`.
- `Makefile`: Automated build script.
- `results/openssl_sm2.txt`: Execution logs and timing data.

## Usage

### Prerequisites
Ensure OpenSSL development headers are installed:

```bash
sudo apt-get install libssl-dev
```

## Run Benchmark

```Bash
make clean
make bench
```

## Methodology

To ensure scientific rigor and eliminate transient system noise, the benchmark follows these constraints:

Warmup: 50 iterations prior to measurement.

Trials: 1000 iterations for each operation (KeyGen, Encrypt, Decrypt).

Payload: Fixed 32-byte (256-bit) plaintext.

Optimization: Compiled with -O3 -march=native.