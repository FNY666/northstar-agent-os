"""Continued fractions.

to_cf(x, max_terms): simple continued fraction expansion.
from_cf(cf): evaluate back to float.
"""

from __future__ import annotations

import math


def to_cf(x: float, max_terms: int = 20) -> list[int]:
    if max_terms < 1:
        raise ValueError("max_terms must be >= 1")
    out = []
    for _ in range(max_terms):
        a = math.floor(x)
        out.append(a)
        frac = x - a
        if frac < 1e-12:
            break
        x = 1.0 / frac
    return out


def from_cf(cf) -> float:
    cf = list(cf)
    if not cf:
        raise ValueError("empty continued fraction")
    result = float(cf[-1])
    for a in reversed(cf[:-1]):
        if result == 0:
            raise ValueError("invalid continued fraction")
        result = a + 1.0 / result
    return result


def main() -> None:
    assert to_cf(3.25) == [3, 4]
    assert abs(from_cf([3, 4, 12, 4]) - 3.245) < 1e-9
    assert to_cf(math.pi)[:4] == [3, 7, 15, 1]
    assert abs(from_cf(to_cf(2.5)) - 2.5) < 1e-9
    print("math_25 OK")


if __name__ == "__main__":
    main()
