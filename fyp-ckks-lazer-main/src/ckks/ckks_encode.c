#include "ckks_encode.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

int ckks_encoder_init(ckks_encoder_t *enc, size_t N, double scale) {
  if (!enc || N == 0 || (N & (N - 1)) != 0) return -1; // N must be power of 2
  if (!(scale > 0.0)) return -2;
  enc->N = N;
  enc->scale = scale;
  return 0;
}

void ckks_plain_coeff_free(ckks_plain_coeff_t *pt) {
  if (!pt) return;
  free(pt->coeff);
  pt->coeff = NULL;
  pt->N = 0;
  pt->scale = 0.0;
}

int ckks_encode_toy(const ckks_encoder_t *enc,
                    ckks_plain_coeff_t *out,
                    const double *vals, size_t nvals)
{
  if (!enc || !out) return -1;
  if (nvals > enc->N) return -2;

  int64_t *c = (int64_t*)calloc(enc->N, sizeof(int64_t));
  if (!c) return -3;

  for (size_t i = 0; i < nvals; i++) {
    double x = vals ? vals[i] : 0.0;
    // round to nearest integer
    c[i] = (int64_t) llround(x * enc->scale);
  }

  out->N = enc->N;
  out->coeff = c;
  out->scale = enc->scale;
  return 0;
}

int ckks_decode_toy(const ckks_encoder_t *enc,
                    double *out_vals, size_t nvals,
                    const ckks_plain_coeff_t *pt)
{
  if (!enc || !pt || !out_vals) return -1;
  if (pt->N != enc->N) return -2;
  if (nvals > enc->N) return -3;

  for (size_t i = 0; i < nvals; i++) {
    out_vals[i] = ((double)pt->coeff[i]) / enc->scale;
  }
  return 0;
}
