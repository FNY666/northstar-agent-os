"""Big-number helpers: factorial digits, Lucas binomial, factorial zeros.

factorial_digits(n): exact decimal digit count of n!.
lucas_binom_mod(n, k, p): C(n, k) mod prime p via Lucas theorem.
trailing_zeros_factorial(n): exponent of 10 in n!.
"""

from __future__ import annotations

import math


def factorial_digits(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    return len(str(math.factorial(n)))


def _small_comb_mod(n: int, k: int, p: int) -> int:
    if k < 0 or k > n:
        return 0
    num, den = 1, 1
    for i in range(1, k + 1):
        num = (num * (n - k + i)) % p
        den = (den * i) % p
    return (num * pow(den, p - 2, p)) % p


def lucas_binom_mod(n: int, k: int, p: int) -> int:
    """C(n, k) mod p for prime p (Lucas theorem)."""
    if p <= 1:
        raise ValueError("p must be > 1")
    if k < 0 or k > n or n < 0:
        return 0
    res = 1
    while n > 0 or k > 0:
        ni, ki = n % p, k % p
        if ki > ni:
            return 0
        res = (res * _small_comb_mod(ni, ki, p)) % p
        n //= p
        k //= p
    return res


def trailing_zeros_factorial(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    total = 0
    while n:
        n //= 5
        total += n
    return total


def main() -> None:
    assert factorial_digits(0) == 1
    assert factorial_digits(5) == 3      # 120
    assert factorial_digits(100) == 158
    assert lucas_binom_mod(10, 3, 7) == 1  # 120 mod 7
    assert lucas_binom_mod(1000, 500, 7) == math.comb(1000, 500) % 7
    assert trailing_zeros_factorial(100) == 24
    assert trailing_zeros_factorial(5) == 1
    print("math_50 OK")


if __name__ == "__main__":
    main()
