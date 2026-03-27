# CIRCL Kyber512 CPAPKE Benchmark

This directory contains the benchmark driver and result files for the
Cloudflare CIRCL Kyber512 CPAPKE reference implementation.

## Purpose

This benchmark is used as an external reference point for comparing our
Lazer-based Module-LWE PKE implementation with an existing public-key
encryption implementation.

The goal is not to claim superior performance, but to show that the PKE
functionality added to Lazer performs within a reasonable and comparable range.

## Benchmark Target

Reference implementation:
- Cloudflare CIRCL
- Scheme: `Kyber512.CPAPKE`

Measured operations:
- Key generation
- Encryption
- Decryption

## Files

- `circl_kyber512_bench.go` — Go benchmark driver
- `go.mod`, `go.sum` — Go module files
- `results/` — stored benchmark outputs

## Requirements

- Go installed
- Internet access on first run to fetch Go dependencies

## One-time setup

From the project root:

```bash
cd ~/fyp-ckks-lazer
mkdir -p third_party/bench_refs
cd third_party/bench_refs
git clone https://github.com/cloudflare/circl.git
```
Then go to this benchmark directory:

```bash
cd ~/fyp-ckks-lazer/benchmarks/circl_kyber512
go mod init circl-kyber512-bench
go get github.com/cloudflare/circl@latest
go mod tidy
```
If go.mod already exists, you do not need to run go mod init again.

## Run Benchmark

```bash
cd ~/fyp-ckks-lazer/benchmarks/circl_kyber512
go run circl_kyber512_bench.go
```
## Save Output

```bash
cd ~/fyp-ckks-lazer/benchmarks/circl_kyber512
mkdir -p results
go run circl_kyber512_bench.go > results/circl_kyber512.txt
```
## Benchmark Configuration
-Scheme: Kyber512.CPAPKE
-Plaintext size: 256 bits (32 bytes)
-Public key size: 800 bytes
-Private key size: 768 bytes
-Ciphertext size: 768 bytes
-Encryption seed size: 32 bytes
-Warmup trials: 50
-Benchmark trials: 1000

## Notes on Fairness

This benchmark measures only the core cryptographic operations exposed by the
CIRCL Kyber512 CPAPKE API.

It does not include:

file I/O
printing overhead
networking
wrapper overhead

The CIRCL Kyber512 plaintext model is fixed by the package API, so it is not
parameterized in the same way as our Module-LWE PKE implementation. Therefore,
comparison is made at the level of benchmark methodology and core operation
timing rather than by matching identical internal scheme parameters.

## Example Output

```text
============================================================
CIRCL Kyber512 CPAPKE Benchmark
============================================================
Scheme                : Kyber512.CPAPKE
Plaintext size        : 256 bits (32 bytes)
Public key size       : 800 bytes
Private key size      : 768 bytes
Ciphertext size       : 768 bytes
Encryption seed size  : 32 bytes
Benchmark trials      : 1000
Warmup trials         : 50
============================================================
KeyGen (ms)           : 0.014107
Encrypt (ms)          : 0.006979
Decrypt (ms)          : 0.001668
============================================================
```