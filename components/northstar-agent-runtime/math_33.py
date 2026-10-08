"""Bisection root finding on a bracketing interval."""

from __future__ import annotations


def bisect_root(f, a: float, b: float, tol: float = 1e-10,
                max_iter: int = 200) -> float:
    fa, fb = f(a), f(b)
    if fa == 0:
        return a
    if fb == 0:
        return b
    if fa * fb > 0:
        raise ValueError("f(a) and f(b) must have opposite signs")
    for _ in range(max_iter):
        mid = (a + b) / 2
        fm = f(mid)
        if fm == 0 or (b - a) / 2 < tol:
            return mid
        if fa * fm < 0:
            b, fb = mid, fm
        else:
            a, fa = mid, fm
    return (a + b) / 2


def main() -> None:
    import math
    root = bisect_root(lambda x: x**2 - 2, 1.0, 2.0)
    assert abs(root - math.sqrt(2)) < 1e-9
    root = bisect_root(lambda x: x**3 - x - 2, 1.0, 2.0)
    assert abs(root - 1.5213797068) < 1e-8
    print("math_33 OK")


if __name__ == "__main__":
    main()
