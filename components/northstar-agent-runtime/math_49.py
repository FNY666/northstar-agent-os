"""Taylor series evaluation for exp / sin / cos.

Argument reduction mod 2*pi keeps sin/cos accurate for large x.
"""

from __future__ import annotations

import math


def taylor_exp(x: float, terms: int = 25) -> float:
    if terms < 1:
        raise ValueError("terms must be >= 1")
    # range reduction: exp(x) = exp(x/2)^2 repeatedly
    k = 0
    while abs(x) > 1.0:
        x /= 2.0
        k += 1
    total, term = 1.0, 1.0
    for n in range(1, terms):
        term *= x / n
        total += term
    return total ** (2**k)


def taylor_sin(x: float, terms: int = 15) -> float:
    if terms < 1:
        raise ValueError("terms must be >= 1")
    x = x % (2 * math.pi)
    total, term = 0.0, x
    for n in range(terms):
        total += term
        term *= -x * x / ((2 * n + 2) * (2 * n + 3))
    return total


def taylor_cos(x: float, terms: int = 15) -> float:
    if terms < 1:
        raise ValueError("terms must be >= 1")
    x = x % (2 * math.pi)
    total, term = 0.0, 1.0
    for n in range(terms):
        total += term
        term *= -x * x / ((2 * n + 1) * (2 * n + 2))
    return total


def main() -> None:
    assert abs(taylor_exp(1.0) - math.e) < 1e-12
    assert abs(taylor_exp(-2.0) - math.exp(-2)) < 1e-10
    assert abs(taylor_sin(math.pi / 6) - 0.5) < 1e-12
    assert abs(taylor_cos(math.pi / 3) - 0.5) < 1e-12
    assert abs(taylor_sin(10.0) - math.sin(10.0)) < 1e-9
    print("math_49 OK")


if __name__ == "__main__":
    main()
