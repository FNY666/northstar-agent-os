"""Ball tree (mock): recursive hypersphere partition, NN search. Stdlib only."""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import List, Optional

def _dist(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

def _centroid(pts):
    n = len(pts)
    return tuple(sum(p[i] for p in pts) / n for i in range(len(pts[0])))

@dataclass
class BallNode:
    center: tuple
    radius: float
    points: List[tuple]
    left: Optional["BallNode"] = None
    right: Optional["BallNode"] = None

def build(pts: List[tuple], leaf_size: int = 2) -> Optional[BallNode]:
    if not pts: return None
    c = _centroid(pts)
    r = max(_dist(c, p) for p in pts)
    if len(pts) <= leaf_size:
        return BallNode(c, r, list(pts))
    # split along widest dimension
    dim = max(range(len(pts[0])), key=lambda i: max(p[i] for p in pts) - min(p[i] for p in pts))
    s = sorted(pts, key=lambda p: p[dim])
    m = len(s) // 2
    return BallNode(c, r, [], build(s[:m], leaf_size), build(s[m:], leaf_size))

def nearest(node, q, best=None):
    if node is None: return best
    if best is not None and _dist(q, node.center) - node.radius >= _dist(q, best):
        return best
    for p in node.points:
        if best is None or _dist(q, p) < _dist(q, best): best = p
    kids = [node.left, node.right]
    kids.sort(key=lambda k: _dist(q, k.center) if k else float("inf"))
    for k in kids: best = nearest(k, q, best)
    return best

def main() -> None:
    pts = [(0, 0), (1, 0), (5, 5), (6, 5)]
    root = build(pts)
    assert nearest(root, (0.5, 0)) in ((0, 0), (1, 0))
    assert nearest(root, (5.5, 5)) in ((5, 5), (6, 5))
    assert nearest(None, (0, 0)) is None
    print("tree_26 Ball tree (mock) OK")

if __name__ == "__main__":
    main()
