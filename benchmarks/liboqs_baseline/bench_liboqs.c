
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h> 

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

void bench_kem(const char *kem_name) {
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (kem == NULL) {
        printf("Error: KEM scheme %s not enabled or found in liboqs!\n", kem_name);
        return;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);

    struct timespec start, end;
    double keygen_ms, encaps_ms, decaps_ms;

    // --- KeyGen Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) OQS_KEM_keypair(kem, public_key, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) OQS_KEM_keypair(kem, public_key, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Encaps Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    encaps_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Decaps Benchmark ---
    for(int i = 0; i < WARMUP_TRIALS; i++) OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    clock_gettime(CLOCK_MONOTONIC, &end);
    decaps_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    printf("=========================================================\n");
    printf("Scheme                : %s\n", kem->method_name);
    printf("Shared secret size    : %zu bits (%zu bytes)\n", kem->length_shared_secret * 8, kem->length_shared_secret);
    printf("Benchmark trials      : %d\n", BENCHMARK_TRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================\n");
    printf("KeyGen (ms)           : %.6f\n", keygen_ms);
    printf("Encaps (ms)           : %.6f\n", encaps_ms);
    printf("Decaps (ms)           : %.6f\n", decaps_ms);
    printf("=========================================================\n\n");

    OQS_KEM_free(kem);
    free(public_key); free(secret_key); free(ciphertext); free(shared_secret_e); free(shared_secret_d);
}

int main() {
    printf("Initializing liboqs benchmarking suite...\n\n");
    bench_kem("Kyber512");
    bench_kem("FrodoKEM-640-AES");
    return 0;
}