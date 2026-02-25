#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "lazer.h"

/* 產生固定 32-byte seed */
static void seed32(uint8_t out[32], uint8_t tag)
{
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(tag + i);
}

int main(void)
{
  /* ====== 1) 設定 N 與 q ====== */
  const unsigned N = 256;
  const uint64_t q_u64 = 12289;

  /* ====== 2) 建立 int_t q（stack buffer） ======
   *
   * int_t 需要：
   *  - nlimbs: limb 數量（64-bit limbs）
   *  - mem:    指向足夠大的內存
   *
   * 12289 < 2^14，所以 1 limb 足夠。
   */
  _ALIGN8 uint8_t q_mem[_sizeof_int_data(/*nlimbs=*/1)];
  int_t q;
  _int_init(q, /*nlimbs=*/1, q_mem);
  int_set_i64(q, (int64_t)q_u64);


  /* ====== 3) 建立 ring（棧上） ====== */
  POLYRING_T(ring, q, N);

  /* ====== 4) alloc polynomials ====== */
  poly_t a, b, c;
  poly_alloc(a, ring);
  poly_alloc(b, ring);
  poly_alloc(c, ring);

  /* ====== 5) 產生隨機 a,b ====== */
  uint8_t s1[32], s2[32];
  seed32(s1, 0xA1);
  seed32(s2, 0xB2);

  poly_brandom(a, /*k=*/2, s1, /*dom=*/1);
  poly_brandom(b, /*k=*/2, s2, /*dom=*/2);

  /* ====== 6) 乘法 + reduction ====== */
  poly_mul(c, a, b);
  poly_mod(c, c);

  /* ====== 7) 輸出 ====== */
  printf("ring: N=%u, q=%llu\n", N, (unsigned long long)q_u64);

  printf("a = ");
  poly_out_str(stdout, 10, a);
  printf("\n");

  printf("b = ");
  poly_out_str(stdout, 10, b);
  printf("\n");

  printf("c = a*b mod q = ");
  poly_out_str(stdout, 10, c);
  printf("\n");

  /* ====== 8) 清理 ====== */
  poly_free(a);
  poly_free(b);
  poly_free(c);

  /* q 是 stack init，不需要 free；如果你們有 _int_clear 也可呼叫，但通常可省略 */

  return 0;
}
