// src/public_key_encryption/module_lwe_pke.h
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "lazer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const polyring_t *ring;   // pointer to ring parameters
  size_t k;                 // module rank
  unsigned int log2q;       // bit-length of modulus for urandom APIs
  int eta;                  // small-noise parameter
} lwe_pke_ctx_struct;

typedef lwe_pke_ctx_struct lwe_pke_ctx_t[1];

typedef struct {
  polymat_t A;   // k x k
  polyvec_t b;   // k
} lwe_pke_pk_struct;
typedef lwe_pke_pk_struct lwe_pke_pk_t[1];

typedef struct {
  polyvec_t s;   // k
} lwe_pke_sk_struct;
typedef lwe_pke_sk_struct lwe_pke_sk_t[1];

typedef struct {
  polyvec_t u;   // k
  poly_t v;      // 1 polynomial
} lwe_pke_ct_struct;
typedef lwe_pke_ct_struct lwe_pke_ct_t[1];

// --- lifecycle ---
int lwe_pke_ctx_init(lwe_pke_ctx_t ctx,
                     const polyring_t *ring,
                     size_t k,
                     unsigned int log2q,
                     int eta);

int lwe_pke_pk_alloc(lwe_pke_pk_t pk, const lwe_pke_ctx_t ctx);
int lwe_pke_sk_alloc(lwe_pke_sk_t sk, const lwe_pke_ctx_t ctx);
int lwe_pke_ct_alloc(lwe_pke_ct_t ct, const lwe_pke_ctx_t ctx);

void lwe_pke_pk_free(lwe_pke_pk_t pk);
void lwe_pke_sk_free(lwe_pke_sk_t sk);
void lwe_pke_ct_free(lwe_pke_ct_t ct);

// --- encode / decode ---
int lwe_pke_encode_bits_poly(const lwe_pke_ctx_t ctx,
                             poly_t m,
                             const uint8_t *msg,
                             size_t msg_bits);

int lwe_pke_decode_poly_bits(const lwe_pke_ctx_t ctx,
                             uint8_t *msg_out,
                             size_t msg_bits,
                             poly_t mrec);

// --- core API ---
int lwe_pke_keygen(const lwe_pke_ctx_t ctx,
                   lwe_pke_pk_t pk,
                   lwe_pke_sk_t sk,
                   const uint8_t seedA[32],
                   const uint8_t seedS[32]);

int lwe_pke_encrypt(const lwe_pke_ctx_t ctx,
                    lwe_pke_ct_t ct,
                    const lwe_pke_pk_t pk,
                    const uint8_t *msg,
                    size_t msg_bits,
                    const uint8_t seedE[32]);

int lwe_pke_decrypt(const lwe_pke_ctx_t ctx,
                    uint8_t *msg_out,
                    size_t msg_bits,
                    const lwe_pke_ct_t ct,
                    const lwe_pke_sk_t sk);

#ifdef __cplusplus
}
#endif