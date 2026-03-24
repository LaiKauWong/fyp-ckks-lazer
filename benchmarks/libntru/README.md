# libntru Benchmark

This directory contains a benchmark driver for the `libntru` reference implementation vendored under:

`third_party/bench_ref/libntru`

It is used as an external baseline for comparing performance and size metrics against the benchmark results of our Lazer-based public-key encryption implementations.

## Purpose

The goal of this benchmark is to provide a consistent reference point for evaluating our Lazer-based scheme-layer implementations against an existing public-key encryption library.

In particular, this benchmark allows us to compare:

- key generation time
- encryption time
- decryption time
- public key size
- private key size
- ciphertext size

The output format is intentionally aligned with other benchmark result files in this repository, such as:

- `benchmarks/circl_kyber512/results/circl_kyber512.txt`

## Benchmark Target

- **Library:** `libntru`
- **Scheme:** `NTRUEncrypt`
- **Parameter set:** `EES443EP1`

Measured operations:

- Key generation
- Encryption
- Decryption

## Files

- `libntru_bench.c` — benchmark driver
- `Makefile` — build, run, and result-generation targets
- `results/` — stored benchmark outputs
- `libntru_makefile_linux.patch` — local patch used when building the vendored `libntru` on this environment

## Benchmark Configuration

- **Plaintext size:** `256 bits (32 bytes)`
- **Benchmark trials:** `1000`
- **Warmup trials:** `50`
- **RNG:** `NTRU_RNG_DEFAULT`

The benchmark reports:

- public key size
- private key size
- ciphertext size
- average key generation time in milliseconds
- average encryption time in milliseconds
- average decryption time in milliseconds

## Build Note

The vendored `libntru` directory is kept clean as an upstream reference.  
If the local environment requires a change to `Makefile.linux`, the patch stored in this directory should be applied before building `libntru`.

From the repository root:

```bash
cd third_party/bench_ref/libntru
git apply ../../../benchmarks/libntru/libntru_makefile_linux.patch
make
```
After building, if you want to restore the vendored reference tree to a clean state:

```bash
git restore Makefile.linux
git clean -fd
```

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
## Notes

- `third_party/bench_ref/libntru` is treated as a vendored reference implementation.
- Environment-specific build fixes should be stored as patch files in this directory rather than committed directly into the vendored submodule.
- Benchmark executables are local build artifacts and should not be committed.