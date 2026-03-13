#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

#define NTRIALS 1000
#define WARMUP_TRIALS 50
#define LWE_K 2
#define LOG2Q 32
#define ETA 2

static void randbytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static double diff_ms(struct timespec a, struct timespec b) {
    double sec = (double)(b.tv_sec - a.tv_sec);
    double nsec = (double)(b.tv_nsec - a.tv_nsec);
    return sec * 1000.0 + nsec / 1e6;
}

int main(void) {
    srand((unsigned)time(NULL));
    lazer_init();

    lwe_pke_ctx_t ctx;
    lwe_pke_pk_t pk;
    lwe_pke_sk_t sk;

    if (lwe_pke_ctx_init(ctx, &_param_ring, LWE_K, LOG2Q, ETA) != 0) return 1;
    if (lwe_pke_pk_alloc(pk, ctx) != 0 || lwe_pke_sk_alloc(sk, ctx) != 0) return 1;

    uint8_t seedA[32], seedS[32];
    randbytes(seedA, 32); 
    randbytes(seedS, 32);
    if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) return 1;

    printf("=================================================================\n");
    printf("Module-LWE PKE Benchmark (Multi-Length Transparent Chunking)\n");
    printf("=================================================================\n");
    printf("Ring source           : demo_params.h\n");
    printf("Module rank (k)       : %d\n", LWE_K);
    printf("log2(q)               : %d\n", LOG2Q);
    printf("Noise parameter (eta) : %d\n", ETA);
    printf("Benchmark trials      : %d\n", NTRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=================================================================\n\n");
    printf("Msg Size   | Success Rate | KeyGen (ms)  | Encrypt (ms) | Decrypt (ms)\n");
    printf("---------------------------------------------------------------------------------\n");

    const size_t test_bitlens[] = {32, 64, 128, 256, 512, 1024};
    size_t ntests = sizeof(test_bitlens) / sizeof(test_bitlens[0]);

    for (size_t ti = 0; ti < ntests; ti++) {
        size_t bitlen = test_bitlens[ti];
        size_t bytelen = (bitlen + 7) / 8;
        size_t chunk_size = 8;
        size_t num_chunks = (bytelen + chunk_size - 1) / chunk_size;

        double t_keygen_ms = 0.0, t_encrypt_ms = 0.0, t_decrypt_ms = 0.0;
        int completed_trials = 0;
        struct timespec ts1, ts2;

        for (int trial = 0; trial < NTRIALS + WARMUP_TRIALS; trial++) {
            // Fix: Add explicit casts for C++ compilation
            uint8_t *msg = (uint8_t *)calloc(1, bytelen);
            uint8_t *dec = (uint8_t *)calloc(1, bytelen);
            randbytes(msg, bytelen);

            randbytes(seedA, 32); 
            randbytes(seedS, 32);
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            int rc_kg = lwe_pke_keygen(ctx, pk, sk, seedA, seedS);
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (rc_kg != 0) { free(msg); free(dec); continue; }
            if (trial >= WARMUP_TRIALS) t_keygen_ms += diff_ms(ts1, ts2);

            // Fix: Add explicit cast for C++ compilation
            lwe_pke_ct_struct *cts = (lwe_pke_ct_struct *)calloc(num_chunks, sizeof(lwe_pke_ct_struct));
            for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_alloc(&cts[c], ctx);

            int enc_ok = 1;
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            for(size_t c = 0; c < num_chunks; c++) {
                uint8_t seedE[32]; randbytes(seedE, 32);
                uint8_t chunk_buf[8] = {0};
                size_t copy_len = (bytelen - c*8 > 8) ? 8 : (bytelen - c*8);
                memcpy(chunk_buf, msg + c*8, copy_len);
                if (lwe_pke_encrypt(ctx, &cts[c], pk, chunk_buf, 64, seedE) != 0) enc_ok = 0;
            }
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (!enc_ok) { 
                for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_free(&cts[c]); 
                free(cts); free(msg); free(dec); continue; 
            }
            if (trial >= WARMUP_TRIALS) t_encrypt_ms += diff_ms(ts1, ts2);

            int dec_ok = 1;
            clock_gettime(CLOCK_MONOTONIC, &ts1);
            for(size_t c = 0; c < num_chunks; c++) {
                uint8_t chunk_buf[8] = {0};
                if (lwe_pke_decrypt(ctx, chunk_buf, 64, &cts[c], sk) != 0) dec_ok = 0;
                size_t copy_len = (bytelen - c*8 > 8) ? 8 : (bytelen - c*8);
                memcpy(dec + c*8, chunk_buf, copy_len);
            }
            clock_gettime(CLOCK_MONOTONIC, &ts2);
            if (trial >= WARMUP_TRIALS) t_decrypt_ms += diff_ms(ts1, ts2);

            if (dec_ok && memcmp(msg, dec, bytelen) == 0) {
                if (trial >= WARMUP_TRIALS) completed_trials++;
            }

            for(size_t c = 0; c < num_chunks; c++) lwe_pke_ct_free(&cts[c]);
            free(cts); free(msg); free(dec);
        }

        if (completed_trials > 0) {
            double avg_kg = t_keygen_ms / completed_trials;
            double avg_enc = t_encrypt_ms / completed_trials;
            double avg_dec = t_decrypt_ms / completed_trials;
            double success_rate = 100.0 * completed_trials / NTRIALS;
            printf("%4zu bits | %6.2f %% | %10.4f   | %10.4f   | %10.4f   \n",
                   bitlen, success_rate, avg_kg, avg_enc, avg_dec);
        } else {
            printf("%4zu bits |   0.00 %% |        N/A   |        N/A   |        N/A   \n", bitlen);
        }
    }
    printf("=================================================================\n");

    lwe_pke_pk_free(pk);
    lwe_pke_sk_free(sk);
    return 0;
}
