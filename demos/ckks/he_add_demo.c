#include <stdio.h>
#include <stdint.h>

#include "lazer.h"
#include "python/demo/demo_params.h"

#include "src/ckks/ckks_encode.h"
#include "src/ckks/ckks_bridge.h"
#include "src/ckks/ckks_he.h"

#ifdef __cplusplus
extern "C" {
#endif
void lazer_init(void);
#ifdef __cplusplus
}
#endif

static void seed32(uint8_t out[32], uint8_t tag) {
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(tag + i);
}

static void print_vec(const char *tag, const double *v, size_t n) {
  printf("%s", tag);
  for (size_t i = 0; i < n; i++) printf("%.10f ", v[i]);
  printf("\n");
}

int main(void)
{
  lazer_init();   // 必須初始化 HEXL

  const size_t N = (size_t)polyring_get_deg(_param_ring);
  int64_t q_i64 = int_get_i64(polyring_get_mod(_param_ring));

  ckks_encoder_t enc;
  ckks_encoder_init(&enc, N, (double)(1ULL<<30));  // 稍微提高 scale

  double m1[4] = {1.0, 2.0, 3.0, 4.0};
  double m2[4] = {10.0, 20.0, 30.0, 40.0};

  print_vec("m1: ", m1, 4);
  print_vec("m2: ", m2, 4);

  ckks_plain_coeff_t pt1 = {0}, pt2 = {0};
  ckks_encode_toy(&enc, &pt1, m1, 4);
  ckks_encode_toy(&enc, &pt2, m2, 4);

  ckks_sk_t sk;
  ckks_pk_t pk;
  ckks_ct2_t ct1, ct2, ct_sum;

  ckks_sk_init(&sk, _param_ring);
  ckks_pk_init(&pk, _param_ring);
  ckks_ct2_init(&ct1, _param_ring);
  ckks_ct2_init(&ct2, _param_ring);
  ckks_ct2_init(&ct_sum, _param_ring);

  uint8_t s_sk[32], s_a[32], s_e[32];
  seed32(s_sk, 0xA1);
  seed32(s_a,  0xA2);
  seed32(s_e,  0xA3);

  ckks_keygen(&sk, &pk, _param_ring, s_sk, s_a, s_e);

  uint8_t s_r1[32], s_e01[32], s_e11[32];
  uint8_t s_r2[32], s_e02[32], s_e12[32];

  seed32(s_r1,  0xB1);
  seed32(s_e01, 0xB2);
  seed32(s_e11, 0xB3);

  seed32(s_r2,  0xC1);
  seed32(s_e02, 0xC2);
  seed32(s_e12, 0xC3);

  ckks_encrypt(&ct1, &pk, &pt1, q_i64, s_r1, s_e01, s_e11);
  ckks_encrypt(&ct2, &pk, &pt2, q_i64, s_r2, s_e02, s_e12);

  // ===== Homomorphic Add =====
  ckks_add(&ct_sum, &ct1, &ct2);

  ckks_plain_coeff_t pt_out = {0};
  ckks_decrypt(&pt_out, &ct_sum, &sk, q_i64, 1);

  double out[4] = {0};
  ckks_decode_toy(&enc, out, 4, &pt_out);

  print_vec("decrypted(m1+m2): ", out, 4);

  // expected
  double expected[4];
  for (int i = 0; i < 4; i++)
    expected[i] = m1[i] + m2[i];

  print_vec("expected:         ", expected, 4);

  return 0;
}