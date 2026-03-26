
# Libsodium X25519 PKE Benchmark

This directory contains the reproducible benchmark driver for Elliptic Curve Public Key Encryption (PKE) using the `libsodium` library.

## Purpose

To provide a rigorous "Modern Classical" baseline for performance comparison. Unlike ECDH (Key Agreement), we use the `crypto_box_seal` API, which implements **Anonymous Public-Key Encryption**. This ensures a perfect semantic match with our Lazer-based PKE, as both encrypt an explicit 256-bit plaintext payload.

## Benchmark Target

- **Library**: `libsodium` (v1.0.18+)
- **Scheme**: `X25519` (Curve25519)
- **Security Level**: ~128-bit (Classical)

## Files

- `bench_libsodium.c`: Unified C driver enforcing 50 warmups and 1000 benchmark trials.
- `Makefile`: Automated build script linking `libsodium`.
- `results/libsodium_x25519.txt`: Benchmark execution logs.

## Requirements

```bash
sudo apt-get install libsodium-dev
```

## Reproducibility (How to Run)

```Bash
cd libsodium_x25519
make clean
make bench
```

## Benchmark Configuration

Payload Size: 256 bits (32 bytes)

Compiler: GCC -O3 -march=native

Methodology: Fixed-trial loop (1000 iterations) to match the evaluation of our proposed Lazer PKE.