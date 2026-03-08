// src/public_key_encryption/module_lwe_pke_bench.c
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "demo_params.h"

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

static double diff_ms(struct timespec a, struct timespec b) {
  double sec = (double)(b.tv_sec - a.tv_sec);
  double nsec = (double)(b.tv_nsec - a.tv_nsec);
  return sec * 1000.0 + nsec / 1e6;
}

static void print_header(void) {
  printf("=================================================================\n");
  printf("Module-LWE PKE Benchmark (Multi-Length Comparison)\n");
  printf("=================================================================\n");
  printf("Ring source           : demo_params.h\n");
  printf("Module rank (k)       : %d\n", LWE_K);
  printf("log2(q)               : %d\n", LOG2Q);
  printf("Noise parameter (eta) : %d\n", ETA);
  printf("Benchmark trials      : %d\n", NTRIALS);
  printf("Warmup trials         : %d\n", WARMUP_TRIALS);
  printf("=================================================================\n\n");
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

  // The sizes we want to compare
  size_t test_bitlens[] = {32, 64};
  int num_bitlens = sizeof(test_bitlens) / sizeof(test_bitlens[0]);

  printf("%-10s | %-12s | %-12s | %-12s | %-12s\n", "Msg Size", "Success Rate", "KeyGen (ms)", "Encrypt (ms)", "Decrypt (ms)");
  printf("---------------------------------------------------------------------------------\n");

  for (int b = 0; b < num_bitlens; b++) {
    size_t bitlen = test_bitlens[b];
    const size_t bytelen = (bitlen + 7) / 8;

    // Warmup
    for (int i = 0; i < WARMUP_TRIALS; i++) {
      uint8_t msg[32] = {0};
      uint8_t dec[32] = {0};
      uint8_t seedA[32], seedS[32], seedE[32];
      randbytes(msg, bytelen);
      randbytes(seedA, 32); randbytes(seedS, 32); randbytes(seedE, 32);

      if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) == 0) {
        if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) == 0) {
          (void)lwe_pke_decrypt(ctx, dec, bitlen, ct, sk);
        }
      }
    }

    int completed_trials = 0;
    int success_trials = 0;
    double t_keygen_ms = 0.0, t_encrypt_ms = 0.0, t_decrypt_ms = 0.0;
    struct timespec ts1, ts2;

    for (int trial = 0; trial < NTRIALS; trial++) {
      uint8_t msg[32] = {0}, dec[32] = {0};
      uint8_t seedA[32], seedS[32], seedE[32];

      randbytes(msg, bytelen);
      randbytes(seedA, 32); randbytes(seedS, 32); randbytes(seedE, 32);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) continue;
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_keygen_ms += diff_ms(ts1, ts2);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) continue;
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_encrypt_ms += diff_ms(ts1, ts2);

      clock_gettime(CLOCK_MONOTONIC, &ts1);
      if (lwe_pke_decrypt(ctx, dec, bitlen, ct, sk) != 0) continue;
      clock_gettime(CLOCK_MONOTONIC, &ts2);
      t_decrypt_ms += diff_ms(ts1, ts2);

      completed_trials++;
      if (memcmp(msg, dec, bytelen) == 0) success_trials++;
    }

    if (completed_trials > 0) {
      double success_rate = 100.0 * (double)success_trials / (double)completed_trials;
      printf("%-6zu bits | %-11.2f%% | %-12.4f | %-12.4f | %-12.4f\n",
             bitlen, success_rate,
             t_keygen_ms / completed_trials,
             t_encrypt_ms / completed_trials,
             t_decrypt_ms / completed_trials);
    }
  }
  printf("=================================================================\n");

  lwe_pke_ct_free(ct);
  lwe_pke_sk_free(sk);
  lwe_pke_pk_free(pk);
  return 0;
}