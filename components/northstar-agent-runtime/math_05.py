"""Modular arithmetic primitives (modulus m > 0).

All results are normalized to [0, m).
"""

from __future__ import annotations


def _check_mod(m: int) -> None:
    if m <= 0:
        raise ValueError("modulus must be positive")


def mod_add(a: int, b: int, m: int) -> int:
    _check_mod(m)
    return (a + b) % m


def mod_sub(a: int, b: int, m: int) -> int:
    _check_mod(m)
    return (a - b) % m


def mod_mul(a: int, b: int, m: int) -> int:
    _check_mod(m)
    return (a * b) % m


def mod_neg(a: int, m: int) -> int:
    _check_mod(m)
    return (-a) % m


def mod_pow(a: int, e: int, m: int) -> int:
    """a**e mod m (e must be non-negative)."""
    _check_mod(m)
    if e < 0:
        raise ValueError("exponent must be non-negative")
    return pow(a, e, m)


def main() -> None:
    assert mod_add(7, 8, 10) == 5
    assert mod_sub(3, 8, 10) == 5
    assert mod_mul(7, 8, 10) == 6
    assert mod_neg(3, 10) == 7
    assert mod_pow(2, 10, 1000) == 24
    assert mod_pow(5, 0, 7) == 1
    print("math_05 OK")


if __name__ == "__main__":
    main()
