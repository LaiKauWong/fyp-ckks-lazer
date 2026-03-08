#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lazer.h"
#include "module_lwe_pke.h"
#include "../../python/demo/demo_params.h"

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

  // args: ctx, ring, k, log2q, eta
  if (lwe_pke_ctx_init(ctx, &_param_ring, 2, 12, 2) != 0) {
    printf("ctx init failed\n");
    return 1;
  }

  if (lwe_pke_pk_alloc(pk, ctx) != 0 ||
      lwe_pke_sk_alloc(sk, ctx) != 0 ||
      lwe_pke_ct_alloc(ct, ctx) != 0) {
    printf("alloc failed\n");
    return 1;
  }

  uint8_t seedA[32], seedS[32], seedE[32];
  randbytes(seedA, 32);
  randbytes(seedS, 32);

  if (lwe_pke_keygen(ctx, pk, sk, seedA, seedS) != 0) {
    printf("keygen failed\n");
    return 1;
  }

 const size_t tests[] = {32, 64, 128};
size_t ntests = sizeof(tests) / sizeof(tests[0]);

for (size_t ti = 0; ti < ntests; ti++) {
  size_t bitlen = tests[ti];
  size_t bytelen = (bitlen + 7) / 8;

  for (int trial = 0; trial < 1000; trial++) {
    uint8_t msg[32] = {0};
    uint8_t dec[32] = {0};

    randbytes(msg, bytelen);
    randbytes(seedE, 32);

    if (lwe_pke_encrypt(ctx, ct, pk, msg, bitlen, seedE) != 0) {
      printf("encrypt failed at bitlen=%zu trial=%d\n", bitlen, trial);
      return 1;
    }

    if (lwe_pke_decrypt(ctx, dec, bitlen, ct, sk) != 0) {
      printf("decrypt failed at bitlen=%zu trial=%d\n", bitlen, trial);
      return 1;
    }

    if (memcmp(msg, dec, bytelen) != 0) {
      printf("FAIL bitlen=%zu trial=%d\n", bitlen, trial);
      printf("msg[0]=0x%02x dec[0]=0x%02x\n", msg[0], dec[0]);
      return 1;
    }
  }

  printf("PASS: bitlen=%zu (1000 trials)\n", bitlen);
}

  lwe_pke_ct_free(ct);
  lwe_pke_sk_free(sk);
  lwe_pke_pk_free(pk);

  printf("All tests passed.\n");
  return 0;
}



