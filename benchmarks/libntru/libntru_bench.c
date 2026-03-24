#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../third_party/bench_ref/libntru/src/encparams.h"
#include "../../third_party/bench_ref/libntru/src/key.h"
#include "../../third_party/bench_ref/libntru/src/ntru.h"
#include "../../third_party/bench_ref/libntru/src/rand.h"

#define WARMUP_TRIALS 50
#define NTRIALS 1000
#define MSG_LEN 32

static double elapsed_ms(struct timespec t0, struct timespec t1) {
    return (t1.tv_sec - t0.tv_sec) * 1000.0 +
           (t1.tv_nsec - t0.tv_nsec) / 1000000.0;
}

int main(void) {
    NtruEncParams params = NTRU_DEFAULT_PARAMS_128_BITS;
    const uint16_t max_len = ntru_max_msg_len(&params);
    const uint16_t pk_len = ntru_pub_len(&params);
    const uint16_t sk_len = ntru_priv_len(&params);
    const uint16_t ct_len = ntru_enc_len(&params);
    uint8_t plain[MSG_LEN];
    uint8_t encrypted[ct_len];
    uint8_t decrypted[max_len];
    uint16_t dec_len = 0;
    NtruEncKeyPair kp;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    double keygen_total = 0.0;
    double encrypt_total = 0.0;
    double decrypt_total = 0.0;

    if (MSG_LEN > max_len) {
        fprintf(stderr, "Message too long for %s: msg_len=%u max_len=%u\n",
                params.name,
                (unsigned)MSG_LEN,
                (unsigned)max_len);
        return 1;
    }

    for (int i = 0; i < MSG_LEN; ++i) {
        plain[i] = (uint8_t)i;
    }

    if (ntru_rand_init(&rand_ctx, &rng) != NTRU_SUCCESS) {
        fprintf(stderr, "ntru_rand_init failed\n");
        return 1;
    }

    for (int i = 0; i < WARMUP_TRIALS; ++i) {
        if (ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS) {
            fprintf(stderr, "warmup keygen failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
    }

    for (int i = 0; i < NTRIALS; ++i) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS) {
            fprintf(stderr, "keygen failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        keygen_total += elapsed_ms(t0, t1);
    }

    if (ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS) {
        fprintf(stderr, "final keygen failed\n");
        ntru_rand_release(&rand_ctx);
        return 1;
    }

    for (int i = 0; i < WARMUP_TRIALS; ++i) {
        if (ntru_encrypt(plain, MSG_LEN, &kp.pub, &params, &rand_ctx, encrypted) != NTRU_SUCCESS) {
            fprintf(stderr, "warmup encrypt failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
    }

    for (int i = 0; i < NTRIALS; ++i) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (ntru_encrypt(plain, MSG_LEN, &kp.pub, &params, &rand_ctx, encrypted) != NTRU_SUCCESS) {
            fprintf(stderr, "encrypt failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        encrypt_total += elapsed_ms(t0, t1);
    }

    if (ntru_encrypt(plain, MSG_LEN, &kp.pub, &params, &rand_ctx, encrypted) != NTRU_SUCCESS) {
        fprintf(stderr, "prep encrypt failed\n");
        ntru_rand_release(&rand_ctx);
        return 1;
    }

    for (int i = 0; i < WARMUP_TRIALS; ++i) {
        dec_len = 0;
        if (ntru_decrypt(encrypted, &kp, &params, decrypted, &dec_len) != NTRU_SUCCESS) {
            fprintf(stderr, "warmup decrypt failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
    }

    for (int i = 0; i < NTRIALS; ++i) {
        struct timespec t0, t1;
        dec_len = 0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (ntru_decrypt(encrypted, &kp, &params, decrypted, &dec_len) != NTRU_SUCCESS) {
            fprintf(stderr, "decrypt failed\n");
            ntru_rand_release(&rand_ctx);
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        decrypt_total += elapsed_ms(t0, t1);
    }

    if (dec_len != MSG_LEN || memcmp(plain, decrypted, MSG_LEN) != 0) {
        fprintf(stderr, "decrypt mismatch\n");
        ntru_rand_release(&rand_ctx);
        return 1;
    }

    if (ntru_rand_release(&rand_ctx) != NTRU_SUCCESS) {
        fprintf(stderr, "ntru_rand_release failed\n");
        return 1;
    }

    printf("=========================================================\n");
    printf("libntru Benchmark\n");
    printf("=========================================================\n");
    printf("Scheme                : NTRUEncrypt (%s)\n", params.name);
    printf("Plaintext size        : %u bits (%u bytes)\n", MSG_LEN * 8, MSG_LEN);
    printf("Public key size       : %u bytes\n", pk_len);
    printf("Private key size      : %u bytes\n", sk_len);
    printf("Ciphertext size       : %u bytes\n", ct_len);
    printf("Encryption seed size  : internal RNG\n");
    printf("Benchmark trials      : %d\n", NTRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================\n");
    printf("KeyGen (ms)           : %.6f\n", keygen_total / NTRIALS);
    printf("Encrypt (ms)          : %.6f\n", encrypt_total / NTRIALS);
    printf("Decrypt (ms)          : %.6f\n", decrypt_total / NTRIALS);
    printf("=========================================================\n\n");

    printf("CSV:\n");
    printf("scheme,msg_bits,keygen_ms,encrypt_ms,decrypt_ms,pk_bytes,sk_bytes,ct_bytes\n");
    printf("libntru_%s,%u,%.6f,%.6f,%.6f,%u,%u,%u\n",
           params.name,
           MSG_LEN * 8,
           keygen_total / NTRIALS,
           encrypt_total / NTRIALS,
           decrypt_total / NTRIALS,
           pk_len,
           sk_len,
           ct_len);

    return 0;
}
