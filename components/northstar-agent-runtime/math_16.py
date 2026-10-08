"""2D/ND geometry helpers.

dist: Euclidean distance between points.
triangle_area: Heron's formula.
polygon_area: shoelace formula.
circle_area, rect_area: elementary areas.
"""

from __future__ import annotations

import math


def dist(p, q) -> float:
    """Euclidean distance between equal-length points."""
    p, q = list(p), list(q)
    if len(p) != len(q):
        raise ValueError("points must have equal dimension")
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(p, q)))


def triangle_area(a, b, c) -> float:
    """Area via Heron's formula."""
    s1, s2, s3 = dist(a, b), dist(b, c), dist(c, a)
    s = (s1 + s2 + s3) / 2
    area_sq = s * (s - s1) * (s - s2) * (s - s3)
    return math.sqrt(max(area_sq, 0.0))


def polygon_area(pts) -> float:
    """Absolute area of a simple polygon (shoelace)."""
    pts = list(pts)
    if len(pts) < 3:
        raise ValueError("need at least 3 points")
    total = 0.0
    n = len(pts)
    for i in range(n):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % n]
        total += x1 * y2 - x2 * y1
    return abs(total) / 2.0


def circle_area(r: float) -> float:
    if r < 0:
        raise ValueError("radius must be non-negative")
    return math.pi * r * r


def rect_area(w: float, h: float) -> float:
    if w < 0 or h < 0:
        raise ValueError("sides must be non-negative")
    return w * h


def main() -> None:
    assert abs(dist((0, 0), (3, 4)) - 5.0) < 1e-9
    assert abs(triangle_area((0, 0), (4, 0), (0, 3)) - 6.0) < 1e-9
    assert abs(polygon_area([(0, 0), (4, 0), (4, 3), (0, 3)]) - 12.0) < 1e-9
    assert abs(circle_area(1) - math.pi) < 1e-12
    assert rect_area(3, 4) == 12
    print("math_16 OK")


if __name__ == "__main__":
    main()
