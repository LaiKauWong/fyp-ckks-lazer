//single block test
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

#define LWE_K  2
#define LOG2Q  12
#define ETA    2
#define NTRIALS 1000

static void randbytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

int main(void) {
    srand((unsigned)time(NULL));
    lazer_init();

    lwe_pke_ctx_t ctx;
    lwe_pke_pk_t pk;
    lwe_pke_sk_t sk;
    lwe_pke_ct_t ct;

    if (lwe_pke_ctx_init(ctx, &_param_ring, LWE_K, LOG2Q, ETA) != 0) {
        printf("ctx init failed\n");
        return 1;
    }

    if (lwe_pke_pk_alloc(pk, ctx) != 0 ||
        lwe_pke_sk_alloc(sk, ctx) != 0 ||
        lwe_pke_ct_alloc(ct, ctx) != 0) {
        printf("alloc failed\n");
        return 1;
    }

    size_t block_bits = lwe_pke_msg_capacity_bits(ctx);
    size_t block_bytes = lwe_pke_msg_capacity_bytes(ctx);
    if (block_bits == 0 || block_bytes == 0) {
        printf("failed to query message capacity\n");
        lwe_pke_ct_free(ct);
        lwe_pke_sk_free(sk);
        lwe_pke_pk_free(pk);
        return 1;
    }

    printf("Single-block payload capacity: %zu bits (%zu bytes)\n",
           block_bits, block_bytes);

    uint8_t seedA[32], seedS[32], seedE[32];
    randbytes(seedA, 32);
    randbytes(seedS, 32);

    if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) {
        printf("keygen failed\n");
        lwe_pke_ct_free(ct);
        lwe_pke_sk_free(sk);
        lwe_pke_pk_free(pk);
        return 1;
    }

    const size_t tests[] = {32, 64};
    size_t ntests = sizeof(tests) / sizeof(tests[0]);

    for (size_t ti = 0; ti < ntests; ti++) {
        size_t bitlen = tests[ti];

        if (bitlen > block_bits) {
            printf("SKIP: bitlen=%zu exceeds single-block capacity %zu\n",
                   bitlen, block_bits);
            continue;
        }

        size_t bytelen = (bitlen + 7) / 8;

        for (int trial = 0; trial < NTRIALS; trial++) {
            uint8_t *msg = (uint8_t *)calloc(1, bytelen);
            uint8_t *dec = (uint8_t *)calloc(1, bytelen);
            if (msg == NULL || dec == NULL) {
                printf("allocation failed\n");
                free(msg);
                free(dec);
                lwe_pke_ct_free(ct);
                lwe_pke_sk_free(sk);
                lwe_pke_pk_free(pk);
                return 1;
            }

            randbytes(msg, bytelen);
            randbytes(seedE, 32);

            if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) {
                printf("encrypt failed at bitlen=%zu trial=%d\n", bitlen, trial);
                free(msg);
                free(dec);
                lwe_pke_ct_free(ct);
                lwe_pke_sk_free(sk);
                lwe_pke_pk_free(pk);
                return 1;
            }

            if (lwe_pke_decrypt(ctx, dec, bitlen, ct, sk) != 0) {
                printf("decrypt failed at bitlen=%zu trial=%d\n", bitlen, trial);
                free(msg);
                free(dec);
                lwe_pke_ct_free(ct);
                lwe_pke_sk_free(sk);
                lwe_pke_pk_free(pk);
                return 1;
            }

            if (memcmp(msg, dec, bytelen) != 0) {
                printf("FAIL bitlen=%zu trial=%d\n", bitlen, trial);
                printf("msg[0]=0x%02x dec[0]=0x%02x\n", msg[0], dec[0]);
                free(msg);
                free(dec);
                lwe_pke_ct_free(ct);
                lwe_pke_sk_free(sk);
                lwe_pke_pk_free(pk);
                return 1;
            }

            free(msg);
            free(dec);
        }

        printf("PASS: bitlen=%zu (%d trials)\n", bitlen, NTRIALS);
    }

    lwe_pke_ct_free(ct);
    lwe_pke_sk_free(sk);
    lwe_pke_pk_free(pk);

    printf("All single-block tests passed.\n");
    return 0;
}