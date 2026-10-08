"""Combinatorics: factorial, permutations, combinations, multinomial."""

from __future__ import annotations

import math


def factorial(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    return math.factorial(n)


def nCr(n: int, r: int) -> int:
    """Binomial coefficient C(n, r)."""
    if not 0 <= r <= n:
        raise ValueError("require 0 <= r <= n")
    return math.comb(n, r)


def nPr(n: int, r: int) -> int:
    """Permutations P(n, r)."""
    if not 0 <= r <= n:
        raise ValueError("require 0 <= r <= n")
    return math.perm(n, r)


def multinomial(*counts: int) -> int:
    """Multinomial coefficient for the given group sizes."""
    if any(c < 0 for c in counts):
        raise ValueError("counts must be non-negative")
    total = sum(counts)
    result = math.factorial(total)
    for c in counts:
        result //= math.factorial(c)
    return result


def main() -> None:
    assert factorial(5) == 120
    assert factorial(0) == 1
    assert nCr(5, 2) == 10
    assert nCr(10, 0) == 1
    assert nPr(5, 2) == 20
    assert multinomial(2, 3) == 10  # 5! / (2! 3!)
    print("math_13 OK")


if __name__ == "__main__":
    main()
