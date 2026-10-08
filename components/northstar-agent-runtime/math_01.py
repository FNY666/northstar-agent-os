"""Prime checking utilities.

is_prime: deterministic trial division with 6k+-1 wheel.
next_prime / prev_prime: nearest primes above / below n.
"""

from __future__ import annotations

import math


def is_prime(n: int) -> bool:
    """True if n is prime (trial division)."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    limit = math.isqrt(n)
    i = 5
    while i <= limit:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def next_prime(n: int) -> int:
    """Smallest prime strictly greater than n."""
    if n < 2:
        return 2
    cand = n + 1 if n % 2 == 0 else n + 2
    while not is_prime(cand):
        cand += 2
    return cand


def prev_prime(n: int) -> int:
    """Largest prime strictly less than n. Raises ValueError if none."""
    if n <= 2:
        raise ValueError("no prime below 2")
    if n == 3:
        return 2
    cand = n - 1 if n % 2 == 0 else n - 2
    while cand >= 2 and not is_prime(cand):
        cand -= 2
    if cand < 2:
        raise ValueError("no prime found")
    return cand


def main() -> None:
    assert is_prime(2) and is_prime(3) and is_prime(17) and is_prime(7919)
    assert not is_prime(0) and not is_prime(1) and not is_prime(-5)
    assert not is_prime(100) and not is_prime(999)
    assert next_prime(10) == 11
    assert next_prime(2) == 3
    assert next_prime(13) == 17
    assert prev_prime(10) == 7
    assert prev_prime(3) == 2
    assert prev_prime(20) == 19
    print("math_01 OK")


if __name__ == "__main__":
    main()
