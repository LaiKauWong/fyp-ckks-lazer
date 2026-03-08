#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
  size_t N;        // ring degree
  double scale;
} ckks_encoder_t;

// Toy plaintext representation (no mod arithmetic yet)
typedef struct {
  size_t N;
  int64_t *coeff;  // length N
  double scale;
} ckks_plain_coeff_t;

int ckks_encoder_init(ckks_encoder_t *enc, size_t N, double scale);
void ckks_plain_coeff_free(ckks_plain_coeff_t *pt);

int ckks_encode_toy(const ckks_encoder_t *enc,
                    ckks_plain_coeff_t *out,
                    const double *vals, size_t nvals);

int ckks_decode_toy(const ckks_encoder_t *enc,
                    double *out_vals, size_t nvals,
                    const ckks_plain_coeff_t *pt);
