"""Newton-Raphson root finding.

newton(f, df, x0): iterate x -= f(x)/df(x) until convergence.
"""

from __future__ import annotations


def newton(f, df, x0: float, tol: float = 1e-10, max_iter: int = 100) -> float:
    x = x0
    for _ in range(max_iter):
        fpx = df(x)
        if fpx == 0:
            raise ValueError("zero derivative")
        step = f(x) / fpx
        x -= step
        if abs(step) < tol:
            return x
    raise ValueError("did not converge")


def main() -> None:
    import math
    root = newton(lambda x: x**2 - 2, lambda x: 2 * x, 1.0)
    assert abs(root - math.sqrt(2)) < 1e-9
    root = newton(lambda x: x**3 - 27, lambda x: 3 * x**2, 5.0)
    assert abs(root - 3.0) < 1e-9
    print("math_32 OK")


if __name__ == "__main__":
    main()
