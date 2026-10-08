"""Miller-Rabin primality test.

Deterministic for n < 2**64 using the first 12 prime bases
(2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37).
"""

from __future__ import annotations

_MR_BASES_64 = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin; deterministic for n < 2**64."""
    if n < 2:
        return False
    if n in _MR_BASES_64:
        return True
    if any(n % p == 0 for p in _MR_BASES_64):
        return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES_64:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def main() -> None:
    assert is_probable_prime(2)
    assert is_probable_prime(7919)
    assert is_probable_prime(2**61 - 1)  # Mersenne prime
    assert not is_probable_prime(1)
    assert not is_probable_prime(100)
    assert not is_probable_prime(561)  # Carmichael
    assert not is_probable_prime(2**64 - 1)
    print("math_15 OK")


if __name__ == "__main__":
    main()
