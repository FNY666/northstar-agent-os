"""Exact rational arithmetic on fractions.Fraction.

radd, rsub, rmul, rdiv, rpow, rfrom (parse "a/b" or float).
"""

from __future__ import annotations

from fractions import Fraction


def _f(x) -> Fraction:
    if isinstance(x, Fraction):
        return x
    if isinstance(x, float):
        return Fraction(x).limit_denominator(10**12)
    return Fraction(x)


def radd(a, b) -> Fraction:
    return _f(a) + _f(b)


def rsub(a, b) -> Fraction:
    return _f(a) - _f(b)


def rmul(a, b) -> Fraction:
    return _f(a) * _f(b)


def rdiv(a, b) -> Fraction:
    b = _f(b)
    if b == 0:
        raise ValueError("division by zero")
    return _f(a) / b


def rpow(a, n: int) -> Fraction:
    return _f(a) ** n


def rfrom(s: str) -> Fraction:
    """Parse 'a/b', 'a', or decimal string."""
    return Fraction(s)


def main() -> None:
    assert radd("1/3", "1/6") == Fraction(1, 2)
    assert rsub(1, "1/4") == Fraction(3, 4)
    assert rmul("2/3", "3/4") == Fraction(1, 2)
    assert rdiv(1, 3) == Fraction(1, 3)
    assert rpow("2/3", 2) == Fraction(4, 9)
    assert rfrom("3/4") == Fraction(3, 4)
    assert rfrom("0.5") == Fraction(1, 2)
    print("math_48 OK")


if __name__ == "__main__":
    main()
