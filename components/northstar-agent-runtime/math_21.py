"""Interpolation helpers.

linear_interp: straight line between two points.
lagrange: Lagrange polynomial through (xs, ys).
"""

from __future__ import annotations


def linear_interp(x: float, x0: float, y0: float, x1: float, y1: float) -> float:
    if x1 == x0:
        raise ValueError("x0 and x1 must differ")
    t = (x - x0) / (x1 - x0)
    return y0 + t * (y1 - y0)


def lagrange(x: float, xs, ys) -> float:
    """Evaluate the Lagrange interpolating polynomial at x."""
    xs, ys = list(xs), list(ys)
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have equal length")
    if len(xs) == 0:
        raise ValueError("need at least one point")
    if len(set(xs)) != len(xs):
        raise ValueError("xs must be distinct")
    total = 0.0
    n = len(xs)
    for i in range(n):
        term = ys[i]
        for j in range(n):
            if i != j:
                term *= (x - xs[j]) / (xs[i] - xs[j])
        total += term
    return total


def main() -> None:
    assert linear_interp(0.5, 0, 0, 1, 10) == 5.0
    assert linear_interp(2, 0, 1, 4, 9) == 5.0
    # quadratic through (0,1),(1,2),(2,5) is x^2+1
    assert abs(lagrange(3, [0, 1, 2], [1, 2, 5]) - 10.0) < 1e-9
    # interpolant hits the nodes
    for xi, yi in zip([0, 1, 2], [1, 2, 5]):
        assert abs(lagrange(xi, [0, 1, 2], [1, 2, 5]) - yi) < 1e-9
    print("math_21 OK")


if __name__ == "__main__":
    main()
