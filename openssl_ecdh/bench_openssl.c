#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

int main() {
    struct timespec start, end;
    double keygen_ms, derive_ms;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);

    EVP_PKEY *pkey_alice = NULL;
    EVP_PKEY *pkey_bob = NULL;

    EVP_PKEY_keygen(ctx, &pkey_bob);

    for(int i = 0; i < WARMUP_TRIALS; i++) {
        EVP_PKEY_keygen(ctx, &pkey_alice);
        EVP_PKEY_free(pkey_alice);
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) {
        EVP_PKEY_keygen(ctx, &pkey_alice);
        if (i < BENCHMARK_TRIALS - 1) EVP_PKEY_free(pkey_alice);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);


    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(pkey_alice, NULL);
    EVP_PKEY_derive_init(derive_ctx);
    EVP_PKEY_derive_set_peer(derive_ctx, pkey_bob);
    
    size_t secret_len;
    EVP_PKEY_derive(derive_ctx, NULL, &secret_len); 
    unsigned char *secret = malloc(secret_len);

    for(int i = 0; i < WARMUP_TRIALS; i++) EVP_PKEY_derive(derive_ctx, secret, &secret_len);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i = 0; i < BENCHMARK_TRIALS; i++) {
        EVP_PKEY_derive(derive_ctx, secret, &secret_len);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    derive_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    printf("=========================================================\n");
    printf("Scheme                : NIST P-256 ECDH (secp256r1)\n");
    printf("Shared secret size    : %zu bits (%zu bytes)\n", secret_len * 8, secret_len);
    printf("Benchmark trials      : %d\n", BENCHMARK_TRIALS);
    printf("Warmup trials         : %d\n", WARMUP_TRIALS);
    printf("=========================================================\n");
    printf("KeyGen (ms)           : %.6f\n", keygen_ms);
    printf("Derive Shared (ms)    : %.6f\n", derive_ms);
    printf("=========================================================\n");

    EVP_PKEY_free(pkey_alice); 
    EVP_PKEY_free(pkey_bob);
    EVP_PKEY_CTX_free(ctx); 
    EVP_PKEY_CTX_free(derive_ctx); 
    free(secret);

    return 0;
}