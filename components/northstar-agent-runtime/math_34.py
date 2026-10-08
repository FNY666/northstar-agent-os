"""Golden-section search for unimodal minimization."""

from __future__ import annotations

import math


def golden_minimize(f, a: float, b: float, tol: float = 1e-8,
                    max_iter: int = 200) -> float:
    """Minimize unimodal f on [a, b]."""
    if a >= b:
        raise ValueError("require a < b")
    gr = (math.sqrt(5) - 1) / 2
    c = b - gr * (b - a)
    d = a + gr * (b - a)
    for _ in range(max_iter):
        if abs(b - a) < tol:
            break
        if f(c) < f(d):
            b, d = d, c
            c = b - gr * (b - a)
        else:
            a, c = c, d
            d = a + gr * (b - a)
    return (a + b) / 2


def main() -> None:
    x = golden_minimize(lambda t: (t - 2) ** 2, 0.0, 5.0)
    assert abs(x - 2.0) < 1e-6
    x = golden_minimize(lambda t: t**2, -3.0, 7.0)
    assert abs(x) < 1e-6
    print("math_34 OK")


if __name__ == "__main__":
    main()
