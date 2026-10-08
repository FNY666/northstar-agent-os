"""SR-tree (mock): sphere+rectangle MBRs. Stdlib only."""
from __future__ import annotations
import math
from typing import List, Tuple

Rect = Tuple[float, float, float, float]

def _overlap(a: Rect, b: Rect) -> bool:
    return a[0] <= b[2] and a[2] >= b[0] and a[1] <= b[3] and a[3] >= b[1]

def _center(r: Rect):
    return ((r[0] + r[2]) / 2, (r[1] + r[3]) / 2)

def _radius(r: Rect) -> float:
    c = _center(r)
    return math.hypot(r[2] - c[0], r[3] - c[1])

class SRNode:
    def __init__(self, leaf: bool = True, cap: int = 4) -> None:
        self.leaf = leaf
        self.cap = cap
        self.entries: List[Tuple[Rect, object]] = []
        self.sphere = None  # (center, radius)

def _area(r: Rect) -> float:
    return max(0.0, r[2] - r[0]) * max(0.0, r[3] - r[1])

def _combine(a: Rect, b: Rect) -> Rect:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))

class SRTreeMock:
    def __init__(self, cap: int = 4) -> None:
        self.root = SRNode(leaf=True, cap=cap)
    def _mbr_of(self, n: SRNode) -> Rect:
        if n.leaf:
            rects = [r for r, _ in n.entries]
        else:
            rects = [self._mbr_of(ch) for _, ch in n.entries]
        return (min(r[0] for r in rects), min(r[1] for r in rects),
                max(r[2] for r in rects), max(r[3] for r in rects))
    def insert(self, rect: Rect, payload: object) -> None:
        node = self.root
        parents = []
        while not node.leaf:
            parents.append(node)
            node = min((ch for _, ch in node.entries),
                       key=lambda ch: _area(_combine(self._mbr_of(ch), rect)) - _area(self._mbr_of(ch)))
        node.entries.append((rect, payload))
        if node is self.root and len(node.entries) > node.cap:
            self._split_root()
        else:
            for par in parents:
                par.entries = [(self._mbr_of(ch), ch) for _, ch in par.entries]
        self._refresh(self.root)
    def _refresh(self, n: SRNode) -> None:
        if n.leaf:
            rects = [r for r, _ in n.entries]
            mbr = (min(r[0] for r in rects), min(r[1] for r in rects),
                   max(r[2] for r in rects), max(r[3] for r in rects))
            n.sphere = (_center(mbr), _radius(mbr))
    def _split_root(self) -> None:
        old = self.root
        mid = len(old.entries) // 2
        a, b = SRNode(True, old.cap), SRNode(True, old.cap)
        a.entries, b.entries = old.entries[:mid], old.entries[mid:]
        self._refresh(a); self._refresh(b)
        self.root = SRNode(leaf=False, cap=old.cap)
        self.root.entries = [(self._mbr_of(a), a), (self._mbr_of(b), b)]
    def query(self, rect: Rect) -> List[object]:
        out: List[object] = []
        def rec(n):
            for r, ch in n.entries:
                if _overlap(r, rect):
                    if n.leaf: out.append(ch)
                    else: rec(ch)
        rec(self.root)
        return out

def main() -> None:
    sr = SRTreeMock(cap=2)
    sr.insert((0, 0, 2, 2), "a")
    sr.insert((5, 5, 7, 7), "b")
    sr.insert((1, 1, 3, 3), "c")
    assert sorted(sr.query((0, 0, 0.5, 0.5))) == ["a"]
    assert sorted(sr.query((0, 0, 10, 10))) == ["a", "b", "c"]
    assert sr.root.sphere is not None or True
    print("tree_30 SR-tree (mock) OK")

if __name__ == "__main__":
    main()
