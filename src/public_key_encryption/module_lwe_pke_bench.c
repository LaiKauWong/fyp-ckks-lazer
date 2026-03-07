#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

#ifndef TEST_BITLEN
#define TEST_BITLEN 64
#endif

#ifndef NTRIALS
#define NTRIALS 1000
#endif

#ifndef WARMUP_TRIALS
#define WARMUP_TRIALS 50
#endif

#ifndef LWE_K
#define LWE_K 2
#endif

#ifndef LOG2Q
#define LOG2Q 6
#endif

#ifndef ETA
#define ETA 2
#endif

static void randbytes(uint8_t *buf, size_t n) {
  for (size_t i = 0; i < n; i++) {
    buf[i] = (uint8_t)(rand() & 0xff);
  }
}

static void print_bits_prefix(const uint8_t *msg, size_t msg_bits, size_t prefix_bits) {
  size_t n = (msg_bits < prefix_bits) ? msg_bits : prefix_bits;
  printf("[");
  for (size_t i = 0; i < n; i++) {
    uint8_t bit = (msg[i >> 3] >> (i & 7)) & 1u;
    printf("%u", bit);
    if (i + 1 != n) {
      printf(", ");
    }
  }
  if (msg_bits > prefix_bits) {
    printf(" ...");
  }
  printf("]");
}

static double diff_ms(struct timespec a, struct timespec b) {
  double sec = (double)(b.tv_sec - a.tv_sec);
  double nsec = (double)(b.tv_nsec - a.tv_nsec);
  return sec * 1000.0 + nsec / 1e6;
}

static void print_header(void) {
  printf("===============================================\n");
  printf("Module-LWE PKE Benchmark\n");
  printf("===============================================\n");
  printf("Ring source           : demo_params.h\n");
  printf("Module rank (k)       : %d\n", LWE_K);
  printf("log2(q)               : %d\n", LOG2Q);
  printf("Noise parameter (eta) : %d\n", ETA);
  printf("Message length        : %d bits\n", TEST_BITLEN);
  printf("Benchmark trials      : %d\n", NTRIALS);
  printf("Warmup trials         : %d\n", WARMUP_TRIALS);
  printf("===============================================\n\n");
}

int main(void) {
  srand((unsigned)time(NULL));
  lazer_init();

  print_header();

  lwe_pke_ctx_t ctx;
  lwe_pke_pk_t pk;
  lwe_pke_sk_t sk;
  lwe_pke_ct_t ct;

  if (lwe_pke_ctx_init(ctx, &_param_ring, LWE_K, LOG2Q, ETA) != 0) {
    printf("Error: context initialization failed.\n");
    return 1;
  }

  if (lwe_pke_pk_alloc(pk, ctx) != 0 ||
      lwe_pke_sk_alloc(sk, ctx) != 0 ||
      lwe_pke_ct_alloc(ct, ctx) != 0) {
    printf("Error: object allocation failed.\n");
    return 1;
  }


  //Single correctness test
  {
    const size_t bitlen = TEST_BITLEN;
    const size_t bytelen = (bitlen + 7) / 8;

    uint8_t msg[32] = {0};
    uint8_t dec[32] = {0};
    uint8_t seedA[32], seedS[32], seedE[32];

    randbytes(msg, bytelen);
    randbytes(seedA, 32);
    randbytes(seedS, 32);
    randbytes(seedE, 32);

    printf("[1] Single Correctness Test\n");
    printf("Input message prefix  : ");
    print_bits_prefix(msg, bitlen, 16);
    printf("\n");

    if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) {
      printf("Result                : key generation failed.\n");
      lwe_pke_ct_free(ct);
      lwe_pke_sk_free(sk);
      lwe_pke_pk_free(pk);
      return 1;
    }

    if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) {
      printf("Result                : encryption failed.\n");
      lwe_pke_ct_free(ct);
      lwe_pke_sk_free(sk);
      lwe_pke_pk_free(pk);
      return 1;
    }

    if (lwe_pke_decrypt(ctx, dec, bitlen, ct, sk) != 0) {
      printf("Result                : decryption failed.\n");
      lwe_pke_ct_free(ct);
      lwe_pke_sk_free(sk);
      lwe_pke_pk_free(pk);
      return 1;
    }

    if (memcmp(msg, dec, bytelen) == 0) {
      printf("Result                : PASS\n\n");
    } else {
      printf("Result                : FAIL (decrypted message mismatch)\n\n");
      lwe_pke_ct_free(ct);
      lwe_pke_sk_free(sk);
      lwe_pke_pk_free(pk);
      return 1;
    }
  }


  //Warmup
  {
    const size_t bitlen = TEST_BITLEN;
    const size_t bytelen = (bitlen + 7) / 8;

    for (int i = 0; i < WARMUP_TRIALS; i++) {
      uint8_t msg[32] = {0};
      uint8_t dec[32] = {0};
      uint8_t seedA[32], seedS[32], seedE[32];

      randbytes(msg, bytelen);
      randbytes(seedA, 32);
      randbytes(seedS, 32);
      randbytes(seedE, 32);

      if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) {
        continue;
      }
      if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) {
        continue;
      }
      (void)lwe_pke_decrypt(ctx, dec, bitlen, ct, sk);
    }
  }


  //3 Timing benchmark
  {
    const size_t bitlen = TEST_BITLEN;
    const size_t bytelen = (bitlen + 7) / 8;

    int completed_trials = 0;
    int success_trials = 0;

    double t_keygen_ms = 0.0;
    double t_encrypt_ms = 0.0;
    double t_decrypt_ms = 0.0;

    struct timespec ts1, ts2;

    for (int trial = 0; trial < NTRIALS; trial++) {
      uint8_t msg[32] = {0};
      uint8_t dec[32] = {0};
      uint8_t seedA[32], seedS[32], seedE[32];

      randbytes(msg, bytelen);
      randbytes(seedA, 32);
      randbytes(seedS, 32);
      randbytes(seedE, 32);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) {
        continue;
      }
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_keygen_ms += diff_ms(ts1, ts2);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) {
        continue;
      }
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_encrypt_ms += diff_ms(ts1, ts2);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_decrypt(ctx, dec, bitlen, ct, sk) != 0) {
        continue;
      }
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_decrypt_ms += diff_ms(ts1, ts2);

      completed_trials++;

      if (memcmp(msg, dec, bytelen) == 0) {
        success_trials++;
      }
    }

    printf("[2] Robustness and Timing Benchmark\n");
    printf("Completed trials      : %d / %d\n", completed_trials, NTRIALS);

    if (completed_trials == 0) {
      printf("Success rate          : N/A\n");
      printf("Average keygen time   : N/A\n");
      printf("Average encrypt time  : N/A\n");
      printf("Average decrypt time  : N/A\n");
    } else {
      printf("Success rate          : %.2f%%\n",
             100.0 * (double)success_trials / (double)completed_trials);
      printf("Average keygen time   : %.3f ms\n",
             t_keygen_ms / (double)completed_trials);
      printf("Average encrypt time  : %.3f ms\n",
             t_encrypt_ms / (double)completed_trials);
      printf("Average decrypt time  : %.3f ms\n",
             t_decrypt_ms / (double)completed_trials);
    }

    printf("===============================================\n");
  }

  lwe_pke_ct_free(ct);
  lwe_pke_sk_free(sk);
  lwe_pke_pk_free(pk);

  return 0;
}