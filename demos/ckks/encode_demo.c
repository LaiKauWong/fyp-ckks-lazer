#include <stdio.h>
#include "../../src/ckks/ckks_encode.h"

int main() {
  ckks_encoder_t enc;
  if (ckks_encoder_init(&enc, 16, (double)(1ULL<<20)) != 0) {
    printf("encoder init failed\n");
    return 1;
  }

  double in[4] = {1.25, -2.5, 3.0, 0.125};
  ckks_plain_coeff_t pt = {0};

  if (ckks_encode_toy(&enc, &pt, in, 4) != 0) {
    printf("encode failed\n");
    return 1;
  }

  printf("coeffs: ");
  for (int i = 0; i < 8; i++) printf("%lld ", (long long)pt.coeff[i]);
  printf("\n");

  double out[4] = {0};
  ckks_decode_toy(&enc, out, 4, &pt);

  printf("decoded: ");
  for (int i = 0; i < 4; i++) printf("%.10f ", out[i]);
  printf("\n");

  ckks_plain_coeff_free(&pt);
  return 0;
}
