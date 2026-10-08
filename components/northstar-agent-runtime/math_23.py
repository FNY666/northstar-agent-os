"""Complex number helpers (built on Python's complex).

cadd, csub, cmul, cdiv, cconj, cabs, cphase, cpolar, crect.
"""

from __future__ import annotations

import cmath
import math


def _c(z) -> complex:
    return complex(z)


def cadd(a, b) -> complex:
    return _c(a) + _c(b)


def csub(a, b) -> complex:
    return _c(a) - _c(b)


def cmul(a, b) -> complex:
    return _c(a) * _c(b)


def cdiv(a, b) -> complex:
    b = _c(b)
    if b == 0:
        raise ValueError("division by zero")
    return _c(a) / b


def cconj(z) -> complex:
    return _c(z).conjugate()


def cabs(z) -> float:
    return abs(_c(z))


def cphase(z) -> float:
    return cmath.phase(_c(z))


def cpolar(z) -> tuple[float, float]:
    """(r, phi) with z = r * exp(i*phi)."""
    return cmath.polar(_c(z))


def crect(r: float, phi: float) -> complex:
    return cmath.rect(r, phi)


def main() -> None:
    assert cadd(1 + 2j, 3 + 4j) == 4 + 6j
    assert cmul(1 + 1j, 1 - 1j) == 2 + 0j
    assert cdiv(1 + 1j, 1 - 1j) == 1j
    assert cconj(3 + 4j) == 3 - 4j
    assert cabs(3 + 4j) == 5.0
    assert abs(cphase(1j) - math.pi / 2) < 1e-12
    r, phi = cpolar(1 + 1j)
    assert abs(r - math.sqrt(2)) < 1e-12 and abs(phi - math.pi / 4) < 1e-12
    print("math_23 OK")


if __name__ == "__main__":
    main()
