"""Gradient descent optimization.

gradient_descent_1d / gradient_descent_nd: vanilla batch gradient
descent with fixed learning rate. Returns (x_opt, f_opt, iters).
"""

from __future__ import annotations

import math


def gradient_descent_1d(f, df, x0: float, lr: float = 0.1, iters: int = 1000,
                       tol: float = 1e-8):
    """Minimize f: R -> R given derivative df."""
    if lr <= 0:
        raise ValueError("lr must be positive")
    x = x0
    for i in range(iters):
        step = lr * df(x)
        x -= step
        if abs(step) < tol:
            return x, f(x), i + 1
    return x, f(x), iters


def gradient_descent_nd(f, grad, x0, lr: float = 0.1, iters: int = 1000,
                        tol: float = 1e-8):
    """Minimize f: R^n -> R given gradient grad."""
    if lr <= 0:
        raise ValueError("lr must be positive")
    x = list(x0)
    for i in range(iters):
        g = grad(x)
        step_norm = math.sqrt(sum(s * s for s in g))
        x = [xi - lr * gi for xi, gi in zip(x, g)]
        if lr * step_norm < tol:
            return x, f(x), i + 1
    return x, f(x), iters


def main() -> None:
    x, fx, _ = gradient_descent_1d(lambda t: t**2, lambda t: 2 * t, 5.0)
    assert abs(x) < 1e-4 and abs(fx) < 1e-8
    x, fx, _ = gradient_descent_1d(lambda t: (t - 3) ** 2 + 5,
                                   lambda t: 2 * (t - 3), 0.0)
    assert abs(x - 3.0) < 1e-4 and abs(fx - 5.0) < 1e-6
    xs, fxs, _ = gradient_descent_nd(
        lambda v: v[0] ** 2 + v[1] ** 2,
        lambda v: [2 * v[0], 2 * v[1]],
        [4.0, -3.0],
    )
    assert math.sqrt(xs[0] ** 2 + xs[1] ** 2) < 1e-4
    print("math_20 OK")


if __name__ == "__main__":
    main()
