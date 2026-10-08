"""Sieve of Eratosthenes.

sieve(n): list of primes <= n.
prime_pi(n): prime counting function.
nth_prime(n): 1-indexed nth prime (Rosser bound).
"""

from __future__ import annotations

import math


def sieve(n: int) -> list[int]:
    """Primes <= n via the sieve of Eratosthenes."""
    if n < 2:
        return []
    is_p = bytearray(b"\x01") * (n + 1)
    is_p[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(n) + 1):
        if is_p[i]:
            start = i * i
            step = i
            is_p[start : n + 1 : step] = b"\x00" * ((n - start) // step + 1)
    return [i for i, v in enumerate(is_p) if v]


def prime_pi(n: int) -> int:
    """Number of primes <= n."""
    return len(sieve(n))


def nth_prime(n: int) -> int:
    """The 1-indexed nth prime."""
    if n < 1:
        raise ValueError("n must be >= 1")
    if n < 6:
        bound = 15
    else:
        bound = int(n * (math.log(n) + math.log(math.log(n)))) + 3
    primes = sieve(bound)
    while len(primes) < n:  # safety net; Rosser bound should suffice
        bound *= 2
        primes = sieve(bound)
    return primes[n - 1]


def main() -> None:
    assert sieve(20) == [2, 3, 5, 7, 11, 13, 17, 19]
    assert sieve(1) == []
    assert sieve(2) == [2]
    assert prime_pi(100) == 25
    assert nth_prime(1) == 2
    assert nth_prime(25) == 97
    print("math_02 OK")


if __name__ == "__main__":
    main()
