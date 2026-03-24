from __future__ import annotations
from typing import Iterable, List
import lazer

def mod_q_list(coeffs: Iterable[int], q: int, d: int) -> List[int]:
    """
    Normalize coeffs into [0, q) and pad/truncate to length d.
    """
    out = [0] * d
    for i, c in enumerate(coeffs):
        if i >= d:
            break
        out[i] = int(c) % int(q)
    return out

def center_mod_q(c: int, q: int) -> int:
    """
    Map c in [0,q) to centered representative in [-q/2, q/2].
    """
    q = int(q)
    c = int(c) % q
    return c if c <= q // 2 else c - q

def to_centered_list(coeffs_mod_q: Iterable[int], q: int) -> List[int]:
    return [center_mod_q(c, q) for c in coeffs_mod_q]

def poly_from_coeffs(ring: lazer.polyring_t, coeffs: Iterable[int]) -> lazer.poly_t:
    """
    Build a LaZer poly_t from a dense coefficient list.
    """
    return lazer.poly_t(ring, list(coeffs))

def coeffs_from_poly(p: lazer.poly_t) -> List[int]:
    """
    Read coefficients from LaZer poly_t as a Python list in [0,q) reps.
    """
    return p.to_list()
