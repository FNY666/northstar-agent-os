"""Numerical integration (quadrature).

trapezoid, simpson (even n), midpoint rules on [a, b].
"""

from __future__ import annotations


def _check(f, a, b, n):
    if n < 1:
        raise ValueError("n must be >= 1")
    if a >= b:
        raise ValueError("require a < b")


def trapezoid(f, a: float, b: float, n: int = 1000) -> float:
    _check(f, a, b, n)
    h = (b - a) / n
    total = 0.5 * (f(a) + f(b))
    for i in range(1, n):
        total += f(a + i * h)
    return total * h


def simpson(f, a: float, b: float, n: int = 1000) -> float:
    _check(f, a, b, n)
    if n % 2:
        n += 1
    h = (b - a) / n
    total = f(a) + f(b)
    for i in range(1, n):
        w = 4 if i % 2 else 2
        total += w * f(a + i * h)
    return total * h / 3


def midpoint(f, a: float, b: float, n: int = 1000) -> float:
    _check(f, a, b, n)
    h = (b - a) / n
    return h * sum(f(a + (i + 0.5) * h) for i in range(n))


def main() -> None:
    f = lambda x: x**2  # noqa: E731
    exact = 1 / 3
    assert abs(trapezoid(f, 0, 1) - exact) < 1e-6
    assert abs(simpson(f, 0, 1) - exact) < 1e-12
    assert abs(midpoint(f, 0, 1) - exact) < 1e-6
    import math
    assert abs(simpson(math.sin, 0, math.pi) - 2.0) < 1e-10
    print("math_19 OK")


if __name__ == "__main__":
    main()
