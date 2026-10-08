"""Integer factorization (trial division).

factorize(n) -> {prime: exponent}.
divisors(n), num_divisors(n), is_squarefree(n).
"""

from __future__ import annotations

import math


def factorize(n: int) -> dict[int, int]:
    if n < 1:
        raise ValueError("n must be >= 1")
    factors: dict[int, int] = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def divisors(n: int) -> list[int]:
    factors = factorize(n)
    divs = [1]
    for p, e in factors.items():
        divs = [d * p**k for d in divs for k in range(e + 1)]
    return sorted(divs)


def num_divisors(n: int) -> int:
    result = 1
    for e in factorize(n).values():
        result *= e + 1
    return result


def is_squarefree(n: int) -> bool:
    return all(e == 1 for e in factorize(n).values())


def main() -> None:
    assert factorize(360) == {2: 3, 3: 2, 5: 1}
    assert factorize(13) == {13: 1}
    assert factorize(1) == {}
    assert divisors(12) == [1, 2, 3, 4, 6, 12]
    assert num_divisors(36) == 9
    assert is_squarefree(30) and not is_squarefree(18)
    print("math_29 OK")


if __name__ == "__main__":
    main()
