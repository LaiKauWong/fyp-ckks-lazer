#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sodium.h>

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

int main() {
    if (sodium_init() < 0) {
        printf("libsodium couldn't be initialized; it is not safe to use.\n");
        return 1;
    }

    int msg_sizes[] = {32, 64, 128, 256, 512, 1024};
    int num_sizes = sizeof(msg_sizes) / sizeof(msg_sizes[0]);
    struct timespec start, end;

    printf("=========================================================================\n");
    printf("Scheme                : Libsodium X25519 (Sealed Box PKE)\n");
    printf("Benchmark trials      : %d\n", BENCHMARK_TRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================================\n");
    printf("Msg(bits)\tKeyGen(ms)\tEncrypt(ms)\tDecrypt(ms)\n");
    printf("-------------------------------------------------------------------------\n");

    for (int s = 0; s < num_sizes; s++) {
        int msg_bits = msg_sizes[s];
        size_t msg_bytes = msg_bits / 8;
        
        uint8_t pk[crypto_box_PUBLICKEYBYTES];
        uint8_t sk[crypto_box_SECRETKEYBYTES];
        uint8_t *pt = calloc(msg_bytes, 1);
        size_t ct_len = msg_bytes + crypto_box_SEALBYTES;
        uint8_t *ct = malloc(ct_len);
        uint8_t *dec = malloc(msg_bytes);

        // --- KeyGen Benchmark ---
        for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_keypair(pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i = 0; i < BENCHMARK_TRIALS; i++) crypto_box_keypair(pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        // --- Encrypt (Seal) Benchmark ---
        for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal(ct, pt, msg_bytes, pk);
        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i = 0; i < BENCHMARK_TRIALS; i++) crypto_box_seal(ct, pt, msg_bytes, pk);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double encrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        // --- Decrypt (Seal Open) Benchmark ---
        for(int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal_open(dec, ct, ct_len, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &start);
        for(int i = 0; i < BENCHMARK_TRIALS; i++) {
            crypto_box_seal_open(dec, ct, ct_len, pk, sk);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        double decrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

        printf("%d\t\t%.6f\t%.6f\t%.6f\n", msg_bits, keygen_ms, encrypt_ms, decrypt_ms);

        free(pt); free(ct); free(dec);
    }
    printf("=========================================================================\n");
    return 0;
}