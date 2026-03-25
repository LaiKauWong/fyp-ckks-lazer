# OpenSSL ECDH Benchmark

This directory contains the benchmark instructions and result files for traditional Elliptic Curve Diffie-Hellman (ECDH) using the widely adopted OpenSSL library.

## Purpose

This benchmark establishes the "Traditional Standard" baseline representing current pre-quantum internet encryption speeds. 

The goal is to show that our Lazer-based Module-LWE PKE performs at a sub-millisecond level that is highly competitive with currently deployed classical cryptography.

## Benchmark Target

Reference implementation:
- System `OpenSSL` C library (v3.0.13)
- Scheme: `NIST P-256 (secp256r1)`

Measured operations:
- Elliptic curve scalar multiplication (Equates to KeyGen / Shared Secret derivation)

## Files

- `results/openssl_ecdh.txt` — stored benchmark outputs and converted summaries

## Requirements

- OpenSSL installed on the Linux system (`sudo apt-get install openssl`)

## Run Benchmark & Save Output

From the benchmark directory:

```bash
cd ~/fyp-ckks-lazer/benchmarks
mkdir -p openssl_ecdh/results
cd openssl_ecdh
# Note: Press Ctrl+C after the 256-bit test completes
make clean
make bench
```
## Benchmark Configuration
Scheme: NIST P-256 (secp256r1)

Plaintext/Scalar size: 256 bits (32 bytes)

Benchmark trials: 10 seconds continuous loop (Time-based Benchmarking)

## Notes on Fairness
To ensure a fair comparison with our millisecond-based (ms) results, the OpenSSL raw output (ops/s) is converted to a single operation latency using the formula: Time (ms) = 1000 / (Total Ops / 10s).