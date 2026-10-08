"""Modular multiplicative inverse via extended Euclid.

modinv(a, m): x with a*x = 1 (mod m); raises ValueError if none.
"""

from __future__ import annotations


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m."""
    if m <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def main() -> None:
    assert modinv(3, 11) == 4  # 3*4 = 12 = 1 mod 11
    assert (17 * modinv(17, 3120)) % 3120 == 1
    assert modinv(1, 7) == 1
    try:
        modinv(6, 9)
        raise AssertionError("should have raised")
    except ValueError:
        pass
    print("math_26 OK")


if __name__ == "__main__":
    main()
