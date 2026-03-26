#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define WARMUP_TRIALS 50
#define BENCHMARK_TRIALS 1000
#define MSG_BYTES 32 // 256-bit payload

double calc_avg_ms(struct timespec start, struct timespec end, int trials) {
    double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    return (elapsed_ns / trials) / 1000000.0;
}

int main() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char pt[MSG_BYTES] = "SM2 256-bit PKE test message..";
    unsigned char *ct = NULL;
    unsigned char *dec = NULL;
    size_t ct_len, dec_len;
    struct timespec start, end;

    // --- 1. KeyGen Benchmark (SM2) ---
    EVP_PKEY_CTX *initial_kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    EVP_PKEY_keygen_init(initial_kctx);
    EVP_PKEY_keygen(initial_kctx, &pkey); 
    EVP_PKEY_CTX_free(initial_kctx);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<BENCHMARK_TRIALS; i++) {
        EVP_PKEY *tmp_pkey = NULL;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
        EVP_PKEY_keygen_init(kctx);
        EVP_PKEY_keygen(kctx, &tmp_pkey);
        EVP_PKEY_free(tmp_pkey);
        EVP_PKEY_CTX_free(kctx);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double keygen_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- 2. Encrypt Benchmark ---
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    
    EVP_PKEY_encrypt(ctx, NULL, &ct_len, pt, MSG_BYTES);
    ct = malloc(ct_len);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<BENCHMARK_TRIALS; i++) {
        size_t tmp_ct_len = ct_len;
        EVP_PKEY_encrypt(ctx, ct, &tmp_ct_len, pt, MSG_BYTES);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double encrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- 3. Decrypt Benchmark ---
    EVP_PKEY_decrypt_init(ctx);
    dec = malloc(ct_len);

    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<BENCHMARK_TRIALS; i++) {
        size_t tmp_dec_len = ct_len;
        EVP_PKEY_decrypt(ctx, dec, &tmp_dec_len, ct, ct_len);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double decrypt_ms = calc_avg_ms(start, end, BENCHMARK_TRIALS);

    // --- Output ---
    printf("=========================================================\n");
    printf("Scheme                : OpenSSL SM2 (National Standard PKE)\n");
    printf("Payload               : %d bits (%d bytes)\n", MSG_BYTES * 8, MSG_BYTES);
    printf("KeyGen (ms)           : %.6f\n", keygen_ms);
    printf("Encrypt (ms)          : %.6f\n", encrypt_ms);
    printf("Decrypt (ms)          : %.6f\n", decrypt_ms);
    printf("=========================================================\n");

    if(ct) free(ct);
    if(dec) free(dec);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    if(pkey) EVP_PKEY_free(pkey);
    return 0;
}