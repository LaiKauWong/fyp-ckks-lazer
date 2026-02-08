from __future__ import annotations
from dataclasses import dataclass
import lazer

@dataclass(frozen=True)
class CKKSContext:
    """
    Minimal CKKS context for integrating with LaZer poly_t.

    Notes:
      - LaZer polyring_t currently asserts d >= 64 in its Python wrapper.
      - We start with a single modulus q (no modulus chain / rescale yet).
    """
    d: int
    q: int
    scale: float

    def __post_init__(self) -> None:
        if self.d < 64:
            raise ValueError("LaZer polyring_t requires d >= 64.")
        if not (0 < int(self.q) < 2**64):
            raise ValueError("q must be < 2^64.")
        object.__setattr__(self, "ring", lazer.polyring_t(int(self.d), int(self.q)))
