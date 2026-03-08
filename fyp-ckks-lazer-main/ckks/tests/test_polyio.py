from ckks.context import CKKSContext
from ckks.polyio import poly_from_coeffs, coeffs_from_poly, to_centered_list, mod_q_list

def test_poly_dense_init_and_readback():
    ctx = CKKSContext(d=64, q=12289, scale=2**10)
    coeffs = [0]*64
    coeffs[3] = 7
    p = poly_from_coeffs(ctx.ring, coeffs)
    got = coeffs_from_poly(p)
    assert got[3] == 7
    assert got[:8] == [0,0,0,7,0,0,0,0]

def test_centering():
    q = 12289
    coeffs_mod = [0, 1, q//2, q//2 + 1, q-1]
    centered = to_centered_list(coeffs_mod, q=q)
    assert centered[0] == 0
    assert centered[1] == 1
    assert centered[2] == q//2
    assert centered[3] == (q//2 + 1) - q
    assert centered[4] == -1

def test_mod_q_list_pad_truncate():
    q = 97
    d = 8
    coeffs_int = [100, -1, 0, 98, 5, 6, 7, 8, 9]
    out = mod_q_list(coeffs_int, q=q, d=d)
    assert len(out) == d
    assert out[0] == 100 % 97
    assert out[1] == (-1) % 97
    assert out[3] == 98 % 97
