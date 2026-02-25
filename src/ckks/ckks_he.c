#include "ckks_he.h"
#include "ckks_bridge.h"
#include <string.h>
#include <stdlib.h>

// helper: seed tags
static void seed32(uint8_t out[32], uint8_t tag) {
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(tag + i);
}

int ckks_sk_init(ckks_sk_t *sk, const polyring_t ring) {
  if (!sk) return -1;
  poly_alloc(sk->s, ring);
  return 0;
}
void ckks_sk_free(ckks_sk_t *sk) {
  if (!sk) return;
  poly_free(sk->s);
}

int ckks_pk_init(ckks_pk_t *pk, const polyring_t ring) {
  if (!pk) return -1;
  poly_alloc(pk->a, ring);
  poly_alloc(pk->b, ring);
  return 0;
}
void ckks_pk_free(ckks_pk_t *pk) {
  if (!pk) return;
  poly_free(pk->a);
  poly_free(pk->b);
}

int ckks_ct2_init(ckks_ct2_t *ct, const polyring_t ring) {
  if (!ct) return -1;
  poly_alloc(ct->c0, ring);
  poly_alloc(ct->c1, ring);
  ct->scale = 1.0;
  return 0;
}
void ckks_ct2_free(ckks_ct2_t *ct) {
  if (!ct) return;
  poly_free(ct->c0);
  poly_free(ct->c1);
}

int ckks_keygen(ckks_sk_t *sk, ckks_pk_t *pk,
                const polyring_t ring,
                const uint8_t seed_sk[32],
                const uint8_t seed_a[32],
                const uint8_t seed_e[32])
{
  if (!sk || !pk) return -1;

  // s small
  poly_brandom(sk->s, /*k=*/2, seed_sk, /*dom=*/11);

  // a uniform mod q
  // poly_urandom needs (mod, log2mod) — easiest is use ring getters
  int_srcptr q = polyring_get_mod(ring);
  unsigned log2q = polyring_get_log2q(ring);
  poly_urandom(pk->a, q, log2q, seed_a, /*dom=*/12);

  // e small
  poly_t e;
  poly_alloc(e, ring);
  poly_brandom(e, /*k=*/2, seed_e, /*dom=*/13);

  // b = -a*s + e  (mod q)
  poly_t as;
  poly_alloc(as, ring);
  poly_mul(as, pk->a, sk->s);   // as = a*s
  poly_mod(as, as);

  poly_set(pk->b, e);           // b = e
  poly_sub(pk->b, pk->b, as, /*crt=*/0);
  poly_mod(pk->b, pk->b);

  poly_free(as);
  poly_free(e);
  return 0;
}

int ckks_encrypt(ckks_ct2_t *ct,
                 ckks_pk_t *pk,
                 const ckks_plain_coeff_t *pt,
                 int64_t q_i64,
                 const uint8_t seed_r[32],
                 const uint8_t seed_e0[32],
                 const uint8_t seed_e1[32])
{
  if (!ct || !pk || !pt) return -1;

  const polyring_srcptr ring = pk->a->ring;

  // r, e0, e1 small
  poly_t r, e0, e1;
  poly_alloc(r, ring);
  poly_alloc(e0, ring);
  poly_alloc(e1, ring);

  poly_brandom(r,  /*k=*/2, seed_r,  /*dom=*/21);
  poly_brandom(e0, /*k=*/2, seed_e0, /*dom=*/22);
  poly_brandom(e1, /*k=*/2, seed_e1, /*dom=*/23);

  // m as poly
  poly_t m;
  poly_alloc(m, ring);
  ckks_plain_to_poly_modq(m, pt, q_i64);

  // c0 = b*r + e0 + m
  poly_mul(ct->c0, pk->b, r);
  poly_mod(ct->c0, ct->c0);
  poly_add(ct->c0, ct->c0, e0, 0);
  poly_mod(ct->c0, ct->c0);
  poly_add(ct->c0, ct->c0, m, 0);
  poly_mod(ct->c0, ct->c0);

  // c1 = a*r + e1
  poly_mul(ct->c1, pk->a, r);
  poly_mod(ct->c1, ct->c1);
  poly_add(ct->c1, ct->c1, e1, 0);
  poly_mod(ct->c1, ct->c1);

  ct->scale = pt->scale;

  poly_free(m);
  poly_free(r);
  poly_free(e0);
  poly_free(e1);
  return 0;
}

int ckks_decrypt(ckks_plain_coeff_t *out_pt,
                 ckks_ct2_t *ct,
                 ckks_sk_t *sk,
                 int64_t q_i64,
                 int centered)
{
  if (!out_pt || !ct || !sk) return -1;

  const polyring_srcptr ring = sk->s->ring;

  poly_t t;
  poly_alloc(t, ring);

  // t = c0 + c1*s
  poly_mul(t, ct->c1, sk->s);
  poly_mod(t, t);
  poly_add(t, t, ct->c0, 0);
  poly_mod(t, t);

  // poly -> coeffs
  out_pt->scale = ct->scale;
  int rc = ckks_poly_to_plain_modq(out_pt, t, q_i64, centered);

  poly_free(t);
  return rc;
}


int ckks_add(ckks_ct2_t *r,
             ckks_ct2_t *a,
             ckks_ct2_t *b)
{
  if (!r || !a || !b) return -1;

  // 確保在 CRT 域
  poly_tocrt(a->c0);
  poly_tocrt(a->c1);
  poly_tocrt(b->c0);
  poly_tocrt(b->c1);

  poly_tocrt(r->c0);
  poly_tocrt(r->c1);

  poly_add(r->c0, a->c0, b->c0, 1);
  poly_add(r->c1, a->c1, b->c1, 1);

  r->scale = a->scale;  // 假設 scale 相同
  return 0;
}