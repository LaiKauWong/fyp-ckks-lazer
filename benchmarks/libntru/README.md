# libntru Benchmark

This directory contains a benchmark driver for the `libntru` reference
implementation bundled under
[`third_party/bench_ref/libntru`](/home/laikau/fyp-ckks-lazer/lazer/third_party/bench_ref/libntru).

## Purpose

This benchmark is used as an external reference point for comparing Lazer's
module public-key encryption benchmarks against a public NTRUEncrypt
implementation.

The output format is intentionally aligned with other benchmark result files in
this repository, such as
[`benchmarks/circl_kyber512/results/circl_kyber512.txt`](/home/laikau/fyp-ckks-lazer/lazer/benchmarks/circl_kyber512/results/circl_kyber512.txt).

## Benchmark Target

- Library: `libntru`
- Scheme: `NTRUEncrypt`
- Parameter set: `NTRU_DEFAULT_PARAMS_128_BITS`

Measured operations:

- Key generation
- Encryption
- Decryption

## Files

- `libntru_bench.c`- benchmark driver
- `Makefile` - build and run targets
- `results/`- stored benchmark outputs

## Benchmark Configuration

- Plaintext size: `256 bits (32 bytes)`
- Benchmark trials: `1000`
- Warmup trials: `50`
- RNG: `NTRU_RNG_DEFAULT`

The benchmark reports:

- public key size
- private key size
- ciphertext size
- average key generation time in milliseconds
- average encryption time in milliseconds
- average decryption time in milliseconds

## Usage

From this directory:

```bash
make build
make run
make results
```

Target behavior:

- `make build` builds `libntru_bench`
- `make run` builds and runs the benchmark
- `make results` builds, runs, and writes output to `results/libntru.txt`
- `make clean` removes the local benchmark binary

## Example

```bash
cd benchmarks/libntru
make results
cat results/libntru.txt
```

## Example Output

```text
=========================================================
libntru Benchmark
=========================================================
Scheme                : NTRUEncrypt (EES443EP1)
Plaintext size        : 256 bits (32 bytes)
Public key size       : 614 bytes
Private key size      : 68 bytes
Ciphertext size       : 610 bytes
Encryption seed size  : internal RNG
Benchmark trials      : 1000
Warmup trials         : 50
=========================================================
KeyGen (ms)           : 0.076725
Encrypt (ms)          : 0.006352
Decrypt (ms)          : 0.007947
=========================================================
```
