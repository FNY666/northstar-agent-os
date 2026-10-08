"""Euler's totient function.

phi(n): count of 1 <= k <= n with gcd(k, n) == 1.
phi_range(n): totients 0..n via sieve.
"""

from __future__ import annotations


def phi(n: int) -> int:
    """Euler's totient of n (n >= 1)."""
    if n < 1:
        raise ValueError("n must be >= 1")
    result = n
    temp = n
    d = 2
    while d * d <= temp:
        if temp % d == 0:
            while temp % d == 0:
                temp //= d
            result -= result // d
        d += 1 if d == 2 else 2
    if temp > 1:
        result -= result // temp
    return result


def phi_range(n: int) -> list[int]:
    """phi(k) for k in 0..n (phi(0) defined as 0)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    phis = list(range(n + 1))
    if n >= 1:
        phis[1] = 1
    for i in range(2, n + 1):
        if phis[i] == i:  # i is prime
            for j in range(i, n + 1, i):
                phis[j] -= phis[j] // i
    if n >= 0:
        phis[0] = 0
    return phis


def main() -> None:
    assert phi(1) == 1
    assert phi(9) == 6
    assert phi(10) == 4
    assert phi(7) == 6
    assert phi(36) == 12
    assert phi_range(10) == [0, 1, 1, 2, 2, 4, 2, 6, 4, 6, 4]
    print("math_14 OK")


if __name__ == "__main__":
    main()
