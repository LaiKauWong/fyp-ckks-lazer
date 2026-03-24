from __future__ import annotations
from typing import Sequence, List
import numpy as np
import lazer

from .context import CKKSContext
from .polyio import mod_q_list, poly_from_coeffs, coeffs_from_poly, to_centered_list

# ----------------------------
# Hook points (YOU implement)
# ----------------------------

def toy_encode_to_integer_coeffs(z: Sequence[complex], d: int, scale: float) -> List[int]:
    """
    TODO: Replace this with your CKKS toy encoder (FFT/Vandermonde).
    Must return a Python list of length d (signed ints are ok).
    """
    raise NotImplementedError("Plug your toy CKKS encoder here (z -> coeffs_int length d).")

def toy_decode_from_integer_coeffs(coeffs_centered: Sequence[int], d: int, scale: float) -> np.ndarray:
    """
    TODO: Replace this with your CKKS toy decoder.
    Must return a numpy array of complex/real slots.
    """
    raise NotImplementedError("Plug your toy CKKS decoder here (coeffs -> z_hat).")

# ----------------------------
# LaZer-integrated wrappers
# ----------------------------

def encode_to_poly(ctx: CKKSContext, z: Sequence[complex]) -> lazer.poly_t:
    coeffs_int = toy_encode_to_integer_coeffs(z, d=ctx.d, scale=ctx.scale)
    coeffs_mod = mod_q_list(coeffs_int, q=ctx.q, d=ctx.d)
    return poly_from_coeffs(ctx.ring, coeffs_mod)

def decode_from_poly(ctx: CKKSContext, p: lazer.poly_t) -> np.ndarray:
    coeffs_mod = coeffs_from_poly(p)
    coeffs_centered = to_centered_list(coeffs_mod, q=ctx.q)
    return toy_decode_from_integer_coeffs(coeffs_centered, d=ctx.d, scale=ctx.scale)
