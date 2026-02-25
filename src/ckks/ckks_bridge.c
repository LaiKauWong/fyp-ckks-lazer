#include "ckks_bridge.h"
#include <stdlib.h>

static inline int64_t mod_norm_i64(int64_t x, int64_t q) {
  // return x mod q in [0, q)
  int64_t r = x % q;
  if (r < 0) r += q;
  return r;
}

int ckks_plain_to_poly_modq(poly_t dst,
                           const ckks_plain_coeff_t *pt,
                           int64_t q_i64)
{
  if (!dst || !pt || !pt->coeff) return -1;
  if (q_i64 <= 1) return -2;

  // dst->coeffs 是 intvec_ptr，intvec_* 參數型別為 intvec_t (array-of-1)，
  // 在 C 參數退化後等價於指標，所以直接傳 dst->coeffs 沒問題。
  unsigned nelems = intvec_get_nelems(dst->coeffs);
  if (pt->N != (size_t)nelems) return -3;

  intvec_set_zero(dst->coeffs);

  for (unsigned i = 0; i < nelems; i++) {
    int64_t v = pt->coeff[i];
    int64_t w = mod_norm_i64(v, q_i64);
    intvec_set_elem_i64(dst->coeffs, i, w);
  }

  return 0;
}

int ckks_poly_to_plain_modq(ckks_plain_coeff_t *pt,
                           poly_t src,
                           int64_t q_i64,
                           int centered)
{
  if (!pt || !src) return -1;
  if (q_i64 <= 1) return -2;

  unsigned nelems = intvec_get_nelems(src->coeffs);

  if (pt->coeff == NULL) {
    pt->coeff = (int64_t*)malloc(sizeof(int64_t) * (size_t)nelems);
    if (!pt->coeff) return -3;
    pt->N = nelems;
  } else {
    if (pt->N != (size_t)nelems) return -4;
  }

  int64_t half = q_i64 / 2;

  for (unsigned i = 0; i < nelems; i++) {
    int64_t v = intvec_get_elem_i64(src->coeffs, i); // typically in [0,q)
    if (centered) {
      // centered lift: map to (-q/2, q/2]
      if (v > half) v -= q_i64;
    }
    pt->coeff[i] = v;
  }

  // scale 由 caller 管（encode 時設定），這裡不動
  return 0;
}