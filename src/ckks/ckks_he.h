#pragma once
#include "lazer.h"
#include "ckks_encode.h"

typedef struct {
  poly_t s;   // secret key polynomial
} ckks_sk_t;

typedef struct {
  poly_t a;   // uniform
  poly_t b;   // b = -a*s + e  (RLWE pk form)
} ckks_pk_t;

typedef struct {
  poly_t c0;
  poly_t c1;
  double scale;
} ckks_ct2_t;

// init/free
int ckks_sk_init(ckks_sk_t *sk, const polyring_t ring);
void ckks_sk_free(ckks_sk_t *sk);

int ckks_pk_init(ckks_pk_t *pk, const polyring_t ring);
void ckks_pk_free(ckks_pk_t *pk);

int ckks_ct2_init(ckks_ct2_t *ct, const polyring_t ring);
void ckks_ct2_free(ckks_ct2_t *ct);

// keygen
int ckks_keygen(ckks_sk_t *sk, ckks_pk_t *pk,
                const polyring_t ring,
                const uint8_t seed_sk[32],
                const uint8_t seed_a[32],
                const uint8_t seed_e[32]);

// encrypt/decrypt (single-modulus toy)
int ckks_encrypt(ckks_ct2_t *ct,
                 ckks_pk_t *pk,
                 const ckks_plain_coeff_t *pt,
                 int64_t q_i64,
                 const uint8_t seed_r[32],
                 const uint8_t seed_e0[32],
                 const uint8_t seed_e1[32]);

int ckks_decrypt(ckks_plain_coeff_t *out_pt,
                 ckks_ct2_t *ct,
                 ckks_sk_t *sk,
                 int64_t q_i64,
                 int centered);

// Homomorphic addition: r = a + b
int ckks_add(ckks_ct2_t *r,
             ckks_ct2_t *a,
             ckks_ct2_t *b);