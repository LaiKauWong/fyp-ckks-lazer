#pragma once
#include <stdint.h>
#include <stddef.h>
#include "lazer.h"
#include "ckks_encode.h"

/*
 * 將 toy plaintext (int64 coeffs, possibly negative) 寫入 poly_t 係數向量。
 * - q_i64: modulus (must fit in int64)
 * - 會把每個 coeff 轉成 [0, q) 表示並寫入 poly->coeffs
 *
 * 注意：此函數不呼叫 poly_mod()，避免 ring 未完整初始化造成崩潰。
 */
int ckks_plain_to_poly_modq(poly_t dst,
                           const ckks_plain_coeff_t *pt,
                           int64_t q_i64);

/*
 * 從 poly_t 讀出係數，回填到 toy plaintext coeffs。
 * - q_i64: modulus，用於 centered lift（把 [0,q) 轉到 (-q/2, q/2]）
 * - centered=1：做 centered lift（建議）
 * - centered=0：保留 [0,q) 值
 *
 * 若 pt->coeff == NULL，會自動 malloc。
 */
int ckks_poly_to_plain_modq(ckks_plain_coeff_t *pt,
                           poly_t src,
                           int64_t q_i64,
                           int centered);