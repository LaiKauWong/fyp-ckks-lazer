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
#define WARMUP_TRIALS 50

double diff_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 +
           (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    struct timespec s, e;
    double t_kg = 0.0;

    // --- KeyGen Benchmark ---
    for (int i = 0; i < WARMUP_TRIALS; i++) {
        crypto_box_keypair(pk, sk);
    }

    clock_gettime(CLOCK_MONOTONIC, &s);
    for (int i = 0; i < NTRIALS; i++) {
        crypto_box_keypair(pk, sk);
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_kg = diff_ms(s, e) / NTRIALS;

    const size_t pt_bits[] = {256}; //modified from {64, 128, 256}

    for (int p = 0; p < 1; p++) { //modified from p < 3
        size_t pt_len = pt_bits[p] / 8;

        unsigned char *pt = malloc(pt_len);
        size_t ct_len = pt_len + crypto_box_SEALBYTES;
        unsigned char *ct = malloc(ct_len);
        unsigned char *dec = malloc(pt_len);

        if (pt == NULL || ct == NULL || dec == NULL) {
            fprintf(stderr, "Allocation failed!\n");
            free(pt);
            free(ct);
            free(dec);
            return 1;
        }

        for (size_t i = 0; i < pt_len; i++) {
            pt[i] = (unsigned char)(i & 0xFF);
        }

        // --- Encrypt Benchmark ---
        double t_enc = 0.0;
        for (int i = 0; i < WARMUP_TRIALS; i++) {
            if (crypto_box_seal(ct, pt, pt_len, pk) != 0) {
                fprintf(stderr, "Warmup encrypt failed!\n");
                free(pt);
                free(ct);
                free(dec);
                return 1;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &s);
        for (int i = 0; i < NTRIALS; i++) {
            if (crypto_box_seal(ct, pt, pt_len, pk) != 0) {
                fprintf(stderr, "Encrypt failed!\n");
                free(pt);
                free(ct);
                free(dec);
                return 1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_enc = diff_ms(s, e) / NTRIALS;

        // Prepare one explicit ciphertext for decrypt benchmark
        if (crypto_box_seal(ct, pt, pt_len, pk) != 0) {
            fprintf(stderr, "Prep encrypt failed!\n");
            free(pt);
            free(ct);
            free(dec);
            return 1;
        }

        // --- Decrypt Benchmark ---
        double t_dec = 0.0;
        for (int i = 0; i < WARMUP_TRIALS; i++) {
            if (crypto_box_seal_open(dec, ct, ct_len, pk, sk) != 0) {
                fprintf(stderr, "Warmup decrypt failed!\n");
                free(pt);
                free(ct);
                free(dec);
                return 1;
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &s);
        for (int i = 0; i < NTRIALS; i++) {
            if (crypto_box_seal_open(dec, ct, ct_len, pk, sk) != 0) {
                fprintf(stderr, "Decrypt failed!\n");
                free(pt);
                free(ct);
                free(dec);
                return 1;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_dec = diff_ms(s, e) / NTRIALS;

        if (memcmp(pt, dec, pt_len) != 0) {
            fprintf(stderr, "Correctness check failed! Mismatch at %zu bits.\n", pt_bits[p]);
            free(pt);
            free(ct);
            free(dec);
            return 1;
        }

        printf("=========================================================\n");
        printf("Libsodium Benchmark\n");
        printf("=========================================================\n");
        printf("Scheme                : X25519+XSalsa20-Poly1305\n");
        printf("Plaintext size        : %zu bits (%zu bytes)\n", pt_bits[p], pt_len);
        printf("Public key size       : %d bytes\n", crypto_box_PUBLICKEYBYTES);
        printf("Private key size      : %d bytes\n", crypto_box_SECRETKEYBYTES);
        printf("Ciphertext size       : %zu bytes\n", ct_len);
        printf("Encryption seed size  : internal RNG\n");
        printf("Benchmark trials      : %d\n", NTRIALS);
        printf("Warmup trials         : %d\n", WARMUP_TRIALS);
        printf("=========================================================\n");
        printf("KeyGen (ms)           : %0.6f\n", t_kg);
        printf("Encrypt (ms)          : %0.6f\n", t_enc);
        printf("Decrypt (ms)          : %0.6f\n", t_dec);
        printf("=========================================================\n\n");
        printf("CSV:\n");
        printf("scheme,msg_bits,keygen_ms,encrypt_ms,decrypt_ms,pk_bytes,sk_bytes,ct_bytes\n");
        printf("libsodium_x25519,%zu,%0.6f,%0.6f,%0.6f,%d,%d,%zu\n", 
               pt_bits[p], t_kg, t_enc, t_dec, crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES, ct_len);

        free(pt);
        free(ct);
        free(dec);
    }

    return 0;
}
