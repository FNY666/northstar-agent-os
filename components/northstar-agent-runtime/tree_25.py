"""Cover tree (mock): leveled nearest-neighbor search. Stdlib only."""
from __future__ import annotations
import math
from typing import List, Optional, Tuple

def _dist(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

class CoverTreeMock:
    def __init__(self, base: float = 2.0) -> None:
        self.base = base
        self.points: List[tuple] = []
    def insert(self, p: tuple) -> None:
        self.points.append(p)
    def _level(self, d: float) -> int:
        if d <= 0: return 0
        lvl = 0
        while self.base ** lvl < d: lvl += 1
        return lvl
    def nearest(self, q: tuple) -> Optional[tuple]:
        best, bd = None, float("inf")
        for p in self.points:
            d = _dist(q, p)
            if d < bd: best, bd = p, d
        return best
    def cover_radius(self, p: tuple) -> float:
        # mock: base^level covering distance to nearest other point
        others = [_dist(p, x) for x in self.points if x != p]
        if not others: return 0.0
        return float(self.base ** self._level(min(others)))

def main() -> None:
    ct = CoverTreeMock()
    for p in [(0, 0), (3, 4), (10, 0)]: ct.insert(p)
    assert ct.nearest((1, 1)) == (0, 0)
    assert ct.cover_radius((0, 0)) == 8.0  # 2^3 covers dist 5
    assert CoverTreeMock().nearest((0, 0)) is None
    print("tree_25 Cover tree (mock) OK")

if __name__ == "__main__":
    main()
