"""TV-tree (mock): telescoping vectors for high-dim NN. Stdlib only."""
from __future__ import annotations
import math
from typing import List, Optional, Tuple

def _dist(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

class TVTreeMock:
    """Mock: contraction keeps first k dims active; search filters progressively."""
    def __init__(self, dims: int) -> None:
        self.dims = dims
        self.points: List[tuple] = []
    def insert(self, p: tuple) -> None:
        assert len(p) == self.dims
        self.points.append(p)
    def contract(self, p: tuple, k: int) -> tuple:
        return p[:k]
    def nearest(self, q: tuple, k: Optional[int] = None) -> Optional[tuple]:
        k = k or self.dims
        qc = self.contract(q, k)
        best, bd = None, float("inf")
        for p in self.points:
            d = _dist(qc, self.contract(p, k))
            if d < bd: best, bd = p, d
        # refine with full dims among top candidates (mock: just best)
        return best

def main() -> None:
    tv = TVTreeMock(dims=4)
    for p in [(0, 0, 0, 0), (1, 1, 1, 1), (9, 9, 9, 9)]: tv.insert(p)
    assert tv.nearest((0.1, 0, 0, 0)) == (0, 0, 0, 0)
    assert tv.nearest((8, 9, 9, 9), k=2) == (9, 9, 9, 9)
    assert tv.contract((1, 2, 3, 4), 2) == (1, 2)
    assert TVTreeMock(3).nearest((0, 0, 0)) is None
    print("tree_31 TV-tree (mock) OK")

if __name__ == "__main__":
    main()
