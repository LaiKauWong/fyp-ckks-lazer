// src/public_key_encryption/module_lwe_pke.c
#include "module_lwe_pke.h"
#include <string.h>

static void poly_copy_fallback(poly_ptr dst, poly_t src) {
  poly_set(dst, src);
}

//local helper for <x,y>
static void polyvec_dot_local(poly_t out, polyvec_t x, polyvec_t y) {
  size_t k = polyvec_get_nelems(x);  //k elements of polyvec x
  poly_set_zero(out);

  poly_t tmp;
  poly_alloc(tmp, polyvec_get_ring(x)); //set new poly tmp which has same poly ring as x

  for (size_t i = 0; i < k; i++) {
    poly_srcptr xi = polyvec_get_elem_src(x, i);
    poly_srcptr yi = polyvec_get_elem_src(y, i);
    // [Fix] Cast to (void *) to explicitly silence const warnings
    poly_mul(tmp, (void *)xi, (void *)yi);
    poly_add(out, out, tmp, 0); //out = out + tmp
  }

  poly_mod(out, out); //modulus 
  poly_free(tmp);
}

//out = A . s
static void polymat_mul_vec_local(polyvec_t out, polymat_t A, polyvec_t s) {
  size_t nrows = polymat_get_nrows(A);
  size_t ncols = polymat_get_ncols(A);

  poly_t acc, tmp;
  poly_alloc(acc, polyvec_get_ring(s));
  poly_alloc(tmp, polyvec_get_ring(s));

  for (size_t i = 0; i < nrows; i++) {
    poly_set_zero(acc);
    for (size_t j = 0; j < ncols; j++) {
      poly_ptr Aij = polymat_get_elem(A, i, j);
      poly_ptr sj  = polyvec_get_elem(s, j);
      poly_mul(tmp, Aij, sj);
      poly_add(acc, acc, tmp, 0);
    }
    poly_mod(acc, acc);
    poly_ptr out_i = polyvec_get_elem(out, i);
    poly_set(out_i, acc);
  }
  poly_free(acc);
  poly_free(tmp);
}

//out = A^T . r
static void polymat_transpose_mul_vec_local(polyvec_t out, polymat_t A, polyvec_t r) {
  size_t nrows = polymat_get_nrows(A); //rows size
  size_t ncols = polymat_get_ncols(A); //col size

  poly_t acc, tmp;
  poly_alloc(acc, polyvec_get_ring(r));
  poly_alloc(tmp, polyvec_get_ring(r));

  for (size_t i = 0; i < ncols; i++) {
    poly_set_zero(acc);
    for (size_t j = 0; j < nrows; j++) {
      poly_ptr Aji = polymat_get_elem(A, j, i);
      poly_ptr rj  = polyvec_get_elem(r, j);
      poly_mul(tmp, Aji, rj);
      poly_add(acc, acc, tmp, 0);
    }
    poly_mod(acc, acc);
    poly_ptr out_i = polyvec_get_elem(out, i);
    poly_set(out_i, acc);
  }
  poly_free(acc);
  poly_free(tmp);
}

// Setup
int lwe_pke_ctx_init(lwe_pke_ctx_t ctx, const polyring_t *ring,
                     size_t k, unsigned int log2q, int eta) {
  if (ctx == NULL || ring == NULL) return -1;
  ctx->ring = ring;
  ctx->k = k;
  ctx->log2q = log2q;
  ctx->eta = eta;
  return 0;
}

int lwe_pke_pk_alloc(lwe_pke_pk_t pk, const lwe_pke_ctx_t ctx) {
  if (pk == NULL || ctx == NULL || ctx->ring == NULL) return -1;
  polymat_alloc(pk->A, *ctx->ring, ctx->k, ctx->k);
  polyvec_alloc(pk->b, *ctx->ring, ctx->k);
  return 0;
}

int lwe_pke_sk_alloc(lwe_pke_sk_t sk, const lwe_pke_ctx_t ctx) {
  if (sk == NULL || ctx == NULL || ctx->ring == NULL) return -1;
  polyvec_alloc(sk->s, *ctx->ring, ctx->k);
  return 0;
}

int lwe_pke_ct_alloc(lwe_pke_ct_t ct, const lwe_pke_ctx_t ctx) {
  if (ct == NULL || ctx == NULL || ctx->ring == NULL) return -1;
  polyvec_alloc(ct->u, *ctx->ring, ctx->k);
  poly_alloc(ct->v, *ctx->ring);
  return 0;
}

void lwe_pke_pk_free(lwe_pke_pk_t pk) {
  if (pk == NULL) return;
  polymat_free(pk->A);
  polyvec_free(pk->b);
}

void lwe_pke_sk_free(lwe_pke_sk_t sk) {
  if (sk == NULL) return;
  polyvec_free(sk->s);
}

void lwe_pke_ct_free(lwe_pke_ct_t ct) {
  if (ct == NULL) return;
  polyvec_free(ct->u);
  poly_free(ct->v);
}

// Encodes a binary message into a polynomial over the target ring.
// For each message bit, coefficient i is set to either 0 or q/2,
// enabling threshold-based recovery during decryption.
// At most one bit is stored per polynomial coefficient.
int lwe_pke_encode_bits_poly(const lwe_pke_ctx_t ctx, poly_t m,
                             const uint8_t *msg, size_t msg_bits) {
  if (ctx == NULL || ctx->ring == NULL || m == NULL || msg == NULL) return -1;

  size_t ncoeffs = intvec_get_nelems(m->coeffs);
  if (msg_bits > ncoeffs) return -2;

  poly_set_zero(m);

  int64_t q_i64 = int_get_i64((*ctx->ring)->q);
  int64_t half = q_i64 / 2;

  for (size_t i = 0; i < msg_bits; i++) {
    uint8_t bit = (msg[i >> 3] >> (i & 7)) & 1u;
    int64_t coeff = bit ? half : 0;
    intvec_set_elem_i64(m->coeffs, i, coeff);
  }

  poly_mod(m, m);
  return 0;
}

int lwe_pke_decode_poly_bits(const lwe_pke_ctx_t ctx, uint8_t *msg_out,
                             size_t msg_bits, poly_t mrec) {
  if (ctx == NULL || ctx->ring == NULL || msg_out == NULL || mrec == NULL) return -1;

  size_t ncoeffs = intvec_get_nelems(mrec->coeffs);
  if (msg_bits > ncoeffs) return -2;

  memset(msg_out, 0, (msg_bits + 7) / 8);

  int64_t q = int_get_i64((*ctx->ring)->q);
  int64_t half = q / 2;

  for (size_t i = 0; i < msg_bits; i++) {
    int64_t x = intvec_get_elem_i64(mrec->coeffs, i);

    int64_t xm = x % q;
    if (xm < 0) xm += q;

    int64_t d0 = xm;
    if (d0 > q - d0) d0 = q - d0;

    int64_t t = xm - half;
    t %= q;
    if (t < 0) t += q;
    int64_t d1 = t;
    if (d1 > q - d1) d1 = q - d1;

    uint8_t bit = (d1 < d0) ? 1u : 0u;
    msg_out[i >> 3] |= (bit << (i & 7));
  }
  return 0;
}

int lwe_pke_keygen(const lwe_pke_ctx_t ctx,
                   lwe_pke_pk_t pk, lwe_pke_sk_t sk,
                   const uint8_t seedA[32], const uint8_t seedS[32]) {
  if (ctx == NULL || pk == NULL || sk == NULL) return -1;

  // [Fix] explicitly cast away const for Lazer APIs to fix warnings
  polymat_urandom((void *)pk->A, (*ctx->ring)->q, ctx->log2q, (void *)seedA, 0);
  polyvec_brandom((void *)sk->s, ctx->eta, (void *)seedS, 0);

  polyvec_t e;
  polyvec_alloc(e, *ctx->ring, ctx->k);
  polyvec_brandom(e, ctx->eta, (void *)seedS, 1);

  polyvec_t As;
  polyvec_alloc(As, *ctx->ring, ctx->k);
  polymat_mul_vec_local(As, (void *)pk->A, (void *)sk->s);

  polyvec_add((void *)pk->b, As, e, 0);

  polyvec_free(As);
  polyvec_free(e);

  return 0;
}

int lwe_pke_encrypt(const lwe_pke_ctx_t ctx,
                    lwe_pke_ct_t ct, const lwe_pke_pk_t pk,
                    const uint8_t *msg, size_t msg_bits,
                    const uint8_t seedE[32]) {
  if (ctx == NULL || pk == NULL || ct == NULL || msg == NULL) return -1;

  poly_t m, e2, br;
  poly_alloc(m,  *ctx->ring);
  poly_alloc(e2, *ctx->ring);
  poly_alloc(br, *ctx->ring);

  int rc = lwe_pke_encode_bits_poly(ctx, m, msg, msg_bits);
  if (rc != 0) {
    poly_free(m); poly_free(e2); poly_free(br);
    return rc;
  }

  polyvec_t r, e1;
  polyvec_alloc(r,  *ctx->ring, ctx->k);
  polyvec_alloc(e1, *ctx->ring, ctx->k);

  // [Fix] Const casts for seeds
  polyvec_brandom(r,  ctx->eta, (void *)seedE, 0);
  polyvec_brandom(e1, ctx->eta, (void *)seedE, 1);
  poly_brandom(e2,    ctx->eta, (void *)seedE, 2);

  polymat_transpose_mul_vec_local((void *)ct->u, (void *)pk->A, r);
  polyvec_add((void *)ct->u, (void *)ct->u, e1, 0);

  polyvec_dot_local(br, (void *)pk->b, r);
  poly_add((void *)ct->v, br, e2, 0);
  poly_add((void *)ct->v, (void *)ct->v, m, 0);
  poly_mod((void *)ct->v, (void *)ct->v);

  polyvec_free(r);
  polyvec_free(e1);
  poly_free(m);
  poly_free(e2);
  poly_free(br);

  return 0;
}

int lwe_pke_decrypt(const lwe_pke_ctx_t ctx,
                    uint8_t *msg_out, size_t msg_bits,
                    const lwe_pke_ct_t ct, const lwe_pke_sk_t sk) {
  if (ctx == NULL || ct == NULL || sk == NULL || msg_out == NULL) return -1;

  poly_t su, mrec;
  poly_alloc(su,   *ctx->ring);
  poly_alloc(mrec, *ctx->ring);

  // [Fix] Const cast for Lazer passing
  polyvec_dot_local(su, (void *)sk->s, (void *)ct->u);

  poly_sub(mrec, (void *)ct->v, su, 0);
  poly_mod(mrec, mrec);

  int rc = lwe_pke_decode_poly_bits(ctx, msg_out, msg_bits, mrec);

  poly_free(su);
  poly_free(mrec);

  return rc;
}

size_t lwe_pke_msg_capacity_bits(const lwe_pke_ctx_t ctx) {
  if (ctx == NULL || ctx->ring == NULL) return 0;

  poly_t tmp;
  poly_alloc(tmp, ctx->ring);

  size_t ncoeffs = intvec_get_nelems(tmp->coeffs);

  poly_free(tmp);
  return ncoeffs;
}

size_t lwe_pke_msg_capacity_bytes(const lwe_pke_ctx_t ctx) {
  size_t bits = lwe_pke_msg_capacity_bits(ctx);
  return (bits + 7) / 8;
}