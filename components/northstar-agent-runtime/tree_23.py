"""VP-tree (mock): vantage-point nearest neighbor in metric space. Stdlib only."""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

@dataclass
class VPNode:
    vp: tuple
    mu: float
    inner: Optional["VPNode"] = None
    outer: Optional["VPNode"] = None

def _euclid(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

class VPTreeMock:
    def __init__(self, points: List[tuple], dist: Callable = _euclid) -> None:
        self.dist = dist
        self.root = self._build(list(points))
    def _build(self, pts):
        if not pts: return None
        vp = pts[0]
        if len(pts) == 1: return VPNode(vp, 0.0)
        ds = sorted(self.dist(vp, p) for p in pts[1:])
        mu = ds[len(ds) // 2]
        inner = [p for p in pts[1:] if self.dist(vp, p) <= mu]
        outer = [p for p in pts[1:] if self.dist(vp, p) > mu]
        return VPNode(vp, mu, self._build(inner), self._build(outer))
    def nearest(self, q: tuple) -> Optional[tuple]:
        best = [None, float("inf")]
        def rec(n):
            if n is None: return
            d = self.dist(q, n.vp)
            if d < best[1]: best[0], best[1] = n.vp, d
            if n.inner is None and n.outer is None: return
            if d <= n.mu:
                rec(n.inner)
                if d + best[1] >= n.mu: rec(n.outer)
            else:
                rec(n.outer)
                if d - best[1] <= n.mu: rec(n.inner)
        rec(self.root)
        return best[0]

def main() -> None:
    pts = [(0, 0), (1, 1), (5, 5), (9, 9)]
    vp = VPTreeMock(pts)
    assert vp.nearest((0.2, 0.1)) == (0, 0)
    assert vp.nearest((8, 8.5)) == (9, 9)
    assert vp.nearest((5, 5)) == (5, 5)
    assert VPTreeMock([]).nearest((0, 0)) is None
    print("tree_23 VP-tree (mock) OK")

if __name__ == "__main__":
    main()
