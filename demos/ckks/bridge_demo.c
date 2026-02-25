#include <stdio.h>
#include <stdint.h>

#include "lazer.h"

#include "src/ckks/ckks_encode.h"
#include "src/ckks/ckks_bridge.h"

// 用已生成且完整初始化的 ring（包含 CRT/NTT 参数）
#include "python/demo/demo_params.h"

static void print_vec(const char *tag, const double *v, size_t n) {
  printf("%s", tag);
  for (size_t i = 0; i < n; i++) printf("%.10f ", v[i]);
  printf("\n");
}

int main(void) {
  // ring degree
  const size_t N = (size_t)polyring_get_deg(_param_ring);

  // 从 ring modulus 读出 q（假设 fits in int64；这些 params 通常都 fits）
  int64_t q_i64 = int_get_i64(polyring_get_mod(_param_ring));
  if (q_i64 <= 1) {
    printf("bad modulus q=%lld\n", (long long)q_i64);
    return 1;
  }

  // encoder: toy scale 2^20
  ckks_encoder_t enc;
  if (ckks_encoder_init(&enc, N, (double)(1ULL << 20)) != 0) {
    printf("encoder init failed (N=%zu)\n", N);
    return 1;
  }

  double in[4] = {1.25, -2.5, 3.0, 0.125};
  print_vec("in:      ", in, 4);

  // toy encode -> coeffs
  ckks_plain_coeff_t pt = {0};
  if (ckks_encode_toy(&enc, &pt, in, 4) != 0) {
    printf("encode failed\n");
    return 1;
  }

  // allocate poly over generated ring
  poly_t m;
  poly_alloc(m, _param_ring);

  // bridge coeffs -> poly coeffs (mod q)
  if (ckks_plain_to_poly_modq(m, &pt, q_i64) != 0) {
    printf("plain_to_poly failed\n");
    return 1;
  }

  // bridge back poly -> coeffs (centered lift)
  ckks_plain_coeff_t pt2 = {0};
  pt2.N = N;
  pt2.scale = pt.scale;
  pt2.coeff = (int64_t*)malloc(sizeof(int64_t) * N);
  if (!pt2.coeff) return 1;

  if (ckks_poly_to_plain_modq(&pt2, m, q_i64, /*centered=*/1) != 0) {
    printf("poly_to_plain failed\n");
    return 1;
  }

  // decode
  double out[4] = {0};
  if (ckks_decode_toy(&enc, out, 4, &pt2) != 0) {
    printf("decode failed\n");
    return 1;
  }
  print_vec("decoded: ", out, 4);

  // cleanup
  poly_free(m);
  ckks_plain_coeff_free(&pt);
  ckks_plain_coeff_free(&pt2);

  return 0;
}