"""Greatest common divisor utilities.

gcd: binary-safe Euclid on non-negative values.
gcd_list: fold over an iterable.
extended_gcd: Bezout coefficients (g, x, y) with a*x + b*y = g.
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Greatest common divisor (Euclid's algorithm)."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def gcd_list(nums) -> int:
    """GCD of an iterable of ints."""
    nums = list(nums)
    if not nums:
        raise ValueError("empty input")
    g = 0
    for x in nums:
        g = gcd(g, x)
    return g


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """(g, x, y) with a*x + b*y == g == gcd(a, b)."""
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def main() -> None:
    assert gcd(12, 18) == 6
    assert gcd(-12, 18) == 6
    assert gcd(0, 5) == 5
    assert gcd(7, 13) == 1
    assert gcd_list([12, 18, 24]) == 6
    g, x, y = extended_gcd(30, 12)
    assert g == 6 and 30 * x + 12 * y == g
    g, x, y = extended_gcd(17, 5)
    assert g == 1 and 17 * x + 5 * y == g
    print("math_03 OK")


if __name__ == "__main__":
    main()
