"""Range tree (mock): 2D orthogonal range query via sorted x-lists. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

Point = Tuple[float, float]

class RangeTreeMock:
    def __init__(self, points: List[Point]) -> None:
        self.by_x = sorted(points, key=lambda p: p[0])
    def query(self, x0: float, x1: float, y0: float, y1: float) -> List[Point]:
        return [p for p in self.by_x
                if x0 <= p[0] <= x1 and y0 <= p[1] <= y1]

def main() -> None:
    rt = RangeTreeMock([(1, 5), (2, 3), (4, 4), (6, 1)])
    assert sorted(rt.query(1, 4, 2, 5)) == [(1, 5), (2, 3), (4, 4)]
    assert rt.query(0, 0, 0, 0) == []
    assert rt.query(0, 10, 0, 10) == [(1, 5), (2, 3), (4, 4), (6, 1)]
    print("tree_22 Range tree (mock) OK")

if __name__ == "__main__":
    main()
