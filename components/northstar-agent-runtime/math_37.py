"""Legendre and Jacobi symbols.

legendre(a, p): 1 / -1 / 0 for odd prime p.
jacobi(a, n): generalization for odd positive n.
"""

from __future__ import annotations


def legendre(a: int, p: int) -> int:
    """Legendre symbol (a/p); p must be an odd prime."""
    if p <= 2 or p % 2 == 0:
        raise ValueError("p must be an odd prime")
    a %= p
    if a == 0:
        return 0
    return 1 if pow(a, (p - 1) // 2, p) == 1 else -1


def jacobi(a: int, n: int) -> int:
    """Jacobi symbol (a/n); n must be positive and odd."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be positive and odd")
    a %= n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def main() -> None:
    assert legendre(2, 7) == 1   # 3^2 = 9 = 2 mod 7
    assert legendre(3, 7) == -1  # non-residue mod 7
    assert legendre(7, 7) == 0
    assert jacobi(2, 15) == 1    # (-1)*(-1)
    assert jacobi(2, 9) == 1
    assert jacobi(5, 9) == 1
    print("math_37 OK")


if __name__ == "__main__":
    main()
