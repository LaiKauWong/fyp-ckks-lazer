// benchmarks/libsodium_x25519/bench_libsodium.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sodium.h>

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000
#define MSG_BYTES 32 // 256 bits

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

int main() {
    if (sodium_init() < 0) {
        printf("libsodium couldn't be initialized; it is not safe to use.\n");
        return 1;
    }

    struct timespec start, end;
    double keygen_ms, encrypt_ms, decrypt_ms;

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];
    uint8_t pt[MSG_BYTES] = {0x42}; // 256-bit dummy plaintext
    uint8_t dec[MSG_BYTES];
    
    size_t ct_len = MSG_BYTES + crypto_box_SEALBYTES;
    uint8_t *ct = malloc(ct_len);

    // --- KeyGen Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_keypair(pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) crypto_box_keypair(pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Encrypt (Seal) Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal(ct, pt, MSG_BYTES, pk);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) crypto_box_seal(ct, pt, MSG_BYTES, pk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    encrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Decrypt (Seal Open) Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal_open(dec, ct, ct_len, pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) {
        if (crypto_box_seal_open(dec, ct, ct_len, pk, sk) != 0) {
            printf("Decryption failed!\n");
            return 1;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    decrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Print Report ---
    printf("=========================================================\n");
    printf("Scheme                : Libsodium X25519 (Sealed Box PKE)\n");
    printf("Plaintext size        : %d bits (%d bytes)\n", MSG_BYTES * 8, MSG_BYTES);
    printf("Ciphertext size       : %zu bytes\n", ct_len);
    printf("Benchmark trials      : %d\n", BENCHMARK_TRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================\n");
    printf("KeyGen (ms)           : %.6f\n", keygen_ms);
    printf("Encrypt (ms)          : %.6f\n", encrypt_ms);
    printf("Decrypt (ms)          : %.6f\n", decrypt_ms);
    printf("=========================================================\n\n");

    printf("CSV:\n");
    printf("scheme,msg_bits,keygen_ms,encrypt_ms,decrypt_ms\n");
    printf("libsodium_x25519,%d,%.6f,%.6f,%.6f\n", MSG_BYTES * 8, keygen_ms, encrypt_ms, decrypt_ms);

    free(ct);
    return 0;
}