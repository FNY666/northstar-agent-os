"""KD-tree: 2D nearest-neighbor search. Stdlib only."""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

Point = Tuple[float, float]

@dataclass
class KDNode:
    point: Point
    left: Optional["KDNode"] = None
    right: Optional["KDNode"] = None
    axis: int = 0

def build(points: List[Point], depth: int = 0) -> Optional[KDNode]:
    if not points: return None
    axis = depth % 2
    pts = sorted(points, key=lambda p: p[axis])
    m = len(pts) // 2
    return KDNode(pts[m], build(pts[:m], depth + 1), build(pts[m + 1:], depth + 1), axis)

def _dist(a: Point, b: Point) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])

def nearest(root, target: Point, best=None):
    if root is None: return best
    if best is None or _dist(target, root.point) < _dist(target, best):
        best = root.point
    axis = root.axis
    near, far = (root.left, root.right) if target[axis] < root.point[axis] else (root.right, root.left)
    best = nearest(near, target, best)
    if abs(target[axis] - root.point[axis]) < _dist(target, best):
        best = nearest(far, target, best)
    return best

def main() -> None:
    pts = [(2, 3), (5, 4), (9, 6), (4, 7), (8, 1), (7, 2)]
    root = build(pts)
    assert nearest(root, (9, 2)) == (8, 1)
    assert nearest(root, (2, 3)) == (2, 3)
    assert nearest(None, (0, 0)) is None
    print("tree_17 KD-tree OK")

if __name__ == "__main__":
    main()
