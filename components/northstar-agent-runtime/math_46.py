"""Quaternion helpers, stored as (w, x, y, z) tuples.

qmul, qconj, qnorm, qnormalize, qrotate (rotate 3D vector).
"""

from __future__ import annotations

import math


def qmul(a, b):
    w1, x1, y1, z1 = a
    w2, x2, y2, z2 = b
    return (
        w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2,
        w1 * x2 + x1 * w2 + y1 * z2 - z1 * y2,
        w1 * y2 - x1 * z2 + y1 * w2 + z1 * x2,
        w1 * z2 + x1 * y2 - y1 * x2 + z1 * w2,
    )


def qconj(q):
    w, x, y, z = q
    return (w, -x, -y, -z)


def qnorm(q) -> float:
    return math.sqrt(sum(c * c for c in q))


def qnormalize(q):
    n = qnorm(q)
    if n == 0:
        raise ValueError("zero quaternion")
    return tuple(c / n for c in q)


def qrotate(v, q):
    """Rotate 3D vector v by unit quaternion q."""
    if len(v) != 3 or len(q) != 4:
        raise ValueError("need 3D vector and quaternion")
    q = qnormalize(q)
    p = (0.0, v[0], v[1], v[2])
    r = qmul(qmul(q, p), qconj(q))
    return (r[1], r[2], r[3])


def main() -> None:
    assert qmul((1, 0, 0, 0), (0, 1, 0, 0)) == (0, 1, 0, 0)
    # i*j = k
    assert qmul((0, 1, 0, 0), (0, 0, 1, 0)) == (0, 0, 0, 1)
    assert qconj((1, 2, 3, 4)) == (1, -2, -3, -4)
    assert abs(qnorm((1, 2, 3, 4)) - math.sqrt(30)) < 1e-12
    # 90-degree rotation about z sends (1,0,0) -> (0,1,0)
    q = (math.cos(math.pi / 4), 0, 0, math.sin(math.pi / 4))
    r = qrotate((1, 0, 0), q)
    assert abs(r[0]) < 1e-9 and abs(r[1] - 1.0) < 1e-9 and abs(r[2]) < 1e-9
    print("math_46 OK")


if __name__ == "__main__":
    main()
