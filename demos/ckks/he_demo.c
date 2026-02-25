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

int main(void) {
  lazer_init();  
  const size_t N = (size_t)polyring_get_deg(_param_ring);
  int64_t q_i64 = int_get_i64(polyring_get_mod(_param_ring));

  ckks_encoder_t enc;
  ckks_encoder_init(&enc, N, (double)(1ULL<<20));

  double in[4] = {1.25, -2.5, 3.0, 0.125};
  print_vec("in:      ", in, 4);

  ckks_plain_coeff_t pt = {0};
  ckks_encode_toy(&enc, &pt, in, 4);

  ckks_sk_t sk;
  ckks_pk_t pk;
  ckks_ct2_t ct;

  ckks_sk_init(&sk, _param_ring);
  ckks_pk_init(&pk, _param_ring);
  ckks_ct2_init(&ct, _param_ring);

  uint8_t s_sk[32], s_a[32], s_e[32];
  seed32(s_sk, 0xA1);
  seed32(s_a,  0xA2);
  seed32(s_e,  0xA3);

  ckks_keygen(&sk, &pk, _param_ring, s_sk, s_a, s_e);

  uint8_t s_r[32], s_e0[32], s_e1[32];
  seed32(s_r,  0xB1);
  seed32(s_e0, 0xB2);
  seed32(s_e1, 0xB3);

  ckks_encrypt(&ct, &pk, &pt, q_i64, s_r, s_e0, s_e1);

  ckks_plain_coeff_t pt_out = {0};
  ckks_decrypt(&pt_out, &ct, &sk, q_i64, /*centered=*/1);

  double out[4] = {0};
  ckks_decode_toy(&enc, out, 4, &pt_out);
  print_vec("decoded: ", out, 4);

  ckks_plain_coeff_free(&pt);
  ckks_plain_coeff_free(&pt_out);
  ckks_ct2_free(&ct);
  ckks_pk_free(&pk);
  ckks_sk_free(&sk);

  return 0;
}