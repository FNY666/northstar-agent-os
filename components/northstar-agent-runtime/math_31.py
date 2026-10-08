"""Arithmetic/geometric sequence helpers and harmonic numbers."""

from __future__ import annotations


def arith_nth(a1, d, n: int):
    if n < 1:
        raise ValueError("n must be >= 1")
    return a1 + (n - 1) * d


def arith_sum(a1, d, n: int):
    if n < 1:
        raise ValueError("n must be >= 1")
    return n * (2 * a1 + (n - 1) * d) / 2


def geom_nth(a1, r, n: int):
    if n < 1:
        raise ValueError("n must be >= 1")
    return a1 * r ** (n - 1)


def geom_sum(a1, r, n: int):
    if n < 1:
        raise ValueError("n must be >= 1")
    if r == 1:
        return a1 * n
    return a1 * (r**n - 1) / (r - 1)


def harmonic(n: int) -> float:
    if n < 1:
        raise ValueError("n must be >= 1")
    return sum(1.0 / k for k in range(1, n + 1))


def main() -> None:
    assert arith_nth(2, 3, 4) == 11
    assert arith_sum(1, 1, 100) == 5050
    assert geom_nth(2, 3, 4) == 54
    assert geom_sum(1, 2, 4) == 15
    assert geom_sum(5, 1, 10) == 50
    assert abs(harmonic(4) - (1 + 1/2 + 1/3 + 1/4)) < 1e-12
    print("math_31 OK")


if __name__ == "__main__":
    main()
