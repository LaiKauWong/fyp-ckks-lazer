#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 统一的 Benchmark 参数
#define NTRIALS 1000
#define WARMUP_TRIALS 100

double diff_ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1000.0 + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}

void print_errors() { ERR_print_errors_fp(stderr); }

int main(void) {
    printf("=== Benchmark: OpenSSL SM2 (PKE) ===\n");

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0) { print_errors(); return 1; }

    struct timespec s, e;
    double t_kg = 0;

    for(int i=0; i<WARMUP_TRIALS; i++) {
        EVP_PKEY *tmp = NULL;
        EVP_PKEY_keygen(kctx, &tmp);
        EVP_PKEY_free(tmp);
    }
    
    EVP_PKEY *pkey = NULL;
    clock_gettime(CLOCK_MONOTONIC, &s);
    for(int i=0; i<NTRIALS; i++) {
        EVP_PKEY *tmp = NULL;
        if(EVP_PKEY_keygen(kctx, &tmp) <= 0) { print_errors(); return 1; }
        if (i == NTRIALS - 1) {
            pkey = tmp; // 保留最后一把钥匙供加解密使用
        } else {
            EVP_PKEY_free(tmp);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &e);
    t_kg = diff_ms(s, e) / NTRIALS;

    int pk_len = i2d_PUBKEY(pkey, NULL);
    int sk_len = i2d_PrivateKey(pkey, NULL);

    printf("\n[Key Generation]\n");
    printf("PK Size : %d bytes (DER)\n", pk_len);
    printf("SK Size : %d bytes (DER)\n", sk_len);
    printf("Time    : %.4f ms\n", t_kg);

    const size_t pt_bits[] = {256}; //modified from {64, 128, 256}

    for (int p = 0; p < 1; p++) { //modified from p < 3
        size_t pt_len = pt_bits[p] / 8;
        unsigned char pt[32];
        for(size_t i=0; i<pt_len; i++) pt[i] = i & 0xFF;

        EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!enc_ctx || EVP_PKEY_encrypt_init(enc_ctx) <= 0) { print_errors(); return 1; }
        
        size_t ct_len = 0;
        if (EVP_PKEY_encrypt(enc_ctx, NULL, &ct_len, pt, pt_len) <= 0) { print_errors(); return 1; }
        unsigned char *ct = malloc(ct_len);

        double t_enc = 0;
        for(int i=0; i<WARMUP_TRIALS; i++) {
            size_t tmp_len = ct_len;
            EVP_PKEY_encrypt(enc_ctx, ct, &tmp_len, pt, pt_len);
        }
        clock_gettime(CLOCK_MONOTONIC, &s);
        for(int i=0; i<NTRIALS; i++) {
            size_t tmp_len = ct_len;
            if (EVP_PKEY_encrypt(enc_ctx, ct, &tmp_len, pt, pt_len) <= 0) { print_errors(); return 1; }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_enc = diff_ms(s, e) / NTRIALS;

        EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!dec_ctx || EVP_PKEY_decrypt_init(dec_ctx) <= 0) { print_errors(); return 1; }
        
        size_t dec_len = 0;
        if (EVP_PKEY_decrypt(dec_ctx, NULL, &dec_len, ct, ct_len) <= 0) { print_errors(); return 1; }
        unsigned char *dec = malloc(dec_len);

        double t_dec = 0;
        for(int i=0; i<WARMUP_TRIALS; i++) {
            size_t tmp_len = dec_len;
            EVP_PKEY_decrypt(dec_ctx, dec, &tmp_len, ct, ct_len);
        }
        clock_gettime(CLOCK_MONOTONIC, &s);
        for(int i=0; i<NTRIALS; i++) {
            size_t tmp_len = dec_len;
            if (EVP_PKEY_decrypt(dec_ctx, dec, &tmp_len, ct, ct_len) <= 0) { print_errors(); return 1; }
        }
        clock_gettime(CLOCK_MONOTONIC, &e);
        t_dec = diff_ms(s, e) / NTRIALS;

        if (memcmp(pt, dec, pt_len) != 0) {
            fprintf(stderr, "Correctness check failed! Mismatch at %zu bits.\n", pt_bits[p]);
            return 1;
        }

        printf("\n[Payload: %3zu bits (%2zu bytes)]\n", pt_bits[p], pt_len);
        printf("CT Size : %zu bytes\n", ct_len);
        printf("Encrypt : %.4f ms\n", t_enc);
        printf("Decrypt : %.4f ms\n", t_dec);

        free(ct); free(dec);
        EVP_PKEY_CTX_free(enc_ctx); EVP_PKEY_CTX_free(dec_ctx);
    }
    
    EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(kctx);
    return 0;
}
