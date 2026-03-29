#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#ifndef CLOCK_MONOTONIC
# ifdef CLOCK_REALTIME
#  define CLOCK_MONOTONIC CLOCK_REALTIME
# else
#  define CLOCK_MONOTONIC 0
# endif
#endif

#define NTRIALS 1000
#define WARMUP_TRIALS 100

double diff_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    printf("=== Benchmark: Libsodium Sealed Box (X25519 + XSalsa20-Poly1305) ===\n");

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    // --- KeyGen Benchmark ---
    struct timespec s, e;
    double t_kg = 0;
    for (int i = 0; i < WARMUP_TRIALS; i++) crypto_box_keypair(pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &s);
    for (int i = 0; i < NTRIALS; i++) {
        crypto_box_keypair(pk, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_kg = diff_ms(s, e) / NTRIALS;

    printf("\n[Key Generation]\n");
    printf("PK Size : %d bytes\n", crypto_box_PUBLICKEYBYTES);
    printf("SK Size : %d bytes\n", crypto_box_SECRETKEYBYTES);
    printf("Time    : %.4f ms\n", t_kg);

    const size_t pt_bits[] = {64, 128, 256};
    
    for (int p = 0; p < 3; p++) {
        size_t pt_len = pt_bits[p] / 8;
        unsigned char pt[32];
        for(size_t i = 0; i < pt_len; i++) pt[i] = i & 0xFF;

        size_t ct_len = pt_len + crypto_box_SEALBYTES;
        unsigned char *ct = malloc(ct_len);
        unsigned char *dec = malloc(pt_len);

        // --- Encrypt Benchmark ---
        double t_enc = 0;
        for (int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal(ct, pt, pt_len, pk);
        clock_gettime(CLOCK_MONOTONIC, &s);
        for (int i = 0; i < NTRIALS; i++) {
            if (crypto_box_seal(ct, pt, pt_len, pk) != 0) {
                fprintf(stderr, "Encrypt failed!\n"); return 1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_enc = diff_ms(s, e) / NTRIALS;

        // --- Decrypt Benchmark ---
        double t_dec = 0;
        for (int i = 0; i < WARMUP_TRIALS; i++) crypto_box_seal_open(dec, ct, ct_len, pk, sk);
        clock_gettime(CLOCK_MONOTONIC, &s);
        for (int i = 0; i < NTRIALS; i++) {
            if (crypto_box_seal_open(dec, ct, ct_len, pk, sk) != 0) {
                fprintf(stderr, "Decrypt failed!\n"); return 1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_dec = diff_ms(s, e) / NTRIALS;

        if (memcmp(pt, dec, pt_len) != 0) {
            fprintf(stderr, "Correctness check failed! Mismatch at %zu bits.\n", pt_bits[p]);
            return 1;
        }

        printf("\n[Payload: %3zu bits (%2zu bytes)]\n", pt_bits[p], pt_len);
        printf("CT Size : %zu bytes\n", ct_len);
        printf("Encrypt : %.4f ms\n", t_enc);
        printf("Decrypt : %.4f ms\n", t_dec);

        free(ct); free(dec);
    }
    return 0;
}