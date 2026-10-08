"""Numerical differentiation via finite differences.

forward_diff: O(h) first derivative.
central_diff: O(h^2) first derivative.
second_central: O(h^2) second derivative.
"""

from __future__ import annotations


def forward_diff(f, x: float, h: float = 1e-5) -> float:
    if h <= 0:
        raise ValueError("h must be positive")
    return (f(x + h) - f(x)) / h


def central_diff(f, x: float, h: float = 1e-5) -> float:
    if h <= 0:
        raise ValueError("h must be positive")
    return (f(x + h) - f(x - h)) / (2 * h)


def second_central(f, x: float, h: float = 1e-4) -> float:
    if h <= 0:
        raise ValueError("h must be positive")
    return (f(x + h) - 2 * f(x) + f(x - h)) / (h * h)


def main() -> None:
    f = lambda x: x**3  # noqa: E731
    assert abs(forward_diff(f, 2.0) - 12.0) < 1e-3
    assert abs(central_diff(f, 2.0) - 12.0) < 1e-8
    assert abs(second_central(f, 2.0) - 12.0) < 1e-3
    g = lambda x: x**2  # noqa: E731
    assert abs(central_diff(g, 3.0) - 6.0) < 1e-9
    print("math_18 OK")


if __name__ == "__main__":
    main()
