"""Vector operations on sequences of floats.

vadd, vsub, vscale, dot, cross3, norm, normalize, angle.
"""

from __future__ import annotations

import math


def _check(u, v=None):
    u = list(u)
    if not u:
        raise ValueError("vector is empty")
    if v is not None:
        v = list(v)
        if len(u) != len(v):
            raise ValueError("dimension mismatch")
        return u, v
    return u


def vadd(u, v):
    u, v = _check(u, v)
    return [a + b for a, b in zip(u, v)]


def vsub(u, v):
    u, v = _check(u, v)
    return [a - b for a, b in zip(u, v)]


def vscale(u, s: float):
    u = _check(u)
    return [a * s for a in u]


def dot(u, v) -> float:
    u, v = _check(u, v)
    return sum(a * b for a, b in zip(u, v))


def cross3(u, v):
    """3D cross product."""
    u, v = _check(u, v)
    if len(u) != 3:
        raise ValueError("cross3 needs 3D vectors")
    return [
        u[1] * v[2] - u[2] * v[1],
        u[2] * v[0] - u[0] * v[2],
        u[0] * v[1] - u[1] * v[0],
    ]


def norm(u) -> float:
    return math.sqrt(dot(u, u))


def normalize(u):
    n = norm(u)
    if n == 0:
        raise ValueError("zero vector")
    return [a / n for a in u]


def angle(u, v) -> float:
    """Angle in radians between u and v."""
    nu, nv = norm(u), norm(v)
    if nu == 0 or nv == 0:
        raise ValueError("zero vector")
    c = max(-1.0, min(1.0, dot(u, v) / (nu * nv)))
    return math.acos(c)


def main() -> None:
    assert vadd([1, 2], [3, 4]) == [4, 6]
    assert vsub([3, 4], [1, 2]) == [2, 2]
    assert vscale([1, 2], 3) == [3, 6]
    assert dot([1, 2, 3], [4, 5, 6]) == 32
    assert cross3([1, 0, 0], [0, 1, 0]) == [0, 0, 1]
    assert abs(norm([3, 4]) - 5.0) < 1e-9
    assert abs(angle([1, 0], [0, 1]) - math.pi / 2) < 1e-9
    print("math_17 OK")


if __name__ == "__main__":
    main()
