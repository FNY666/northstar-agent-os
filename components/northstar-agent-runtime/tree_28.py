"""X-tree (mock): R-tree variant with supernodes for high overlap. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

Rect = Tuple[float, float, float, float]

def _overlap(a: Rect, b: Rect) -> bool:
    return a[0] <= b[2] and a[2] >= b[0] and a[1] <= b[3] and a[3] >= b[1]

def _area(r: Rect) -> float:
    return max(0.0, r[2] - r[0]) * max(0.0, r[3] - r[1])

def _combine(a: Rect, b: Rect) -> Rect:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))

def _mbr(entries) -> Rect:
    return (min(r[0] for r, _ in entries), min(r[1] for r, _ in entries),
            max(r[2] for r, _ in entries), max(r[3] for r, _ in entries))

class XTreeMock:
    def __init__(self, cap: int = 4) -> None:
        self.cap = cap
        self.entries: List[Tuple[Rect, object]] = []
        self.children: List["XTreeMock"] = []
        self.supernode = False
    def insert(self, rect: Rect, payload: object) -> None:
        if self.children:
            child = min(self.children,
                        key=lambda c: _area(_combine(_mbr(c.entries), rect)) - _area(_mbr(c.entries)))
            child.entries.append((rect, payload))
            return
        self.entries.append((rect, payload))
        if len(self.entries) > self.cap and not self.supernode:
            if self._heavy_overlap():
                # refuse a bad split: grow a supernode instead
                self.supernode = True
            else:
                mid = len(self.entries) // 2
                a, b = XTreeMock(self.cap), XTreeMock(self.cap)
                a.entries = self.entries[:mid]
                b.entries = self.entries[mid:]
                self.entries = []
                self.children = [a, b]
    def _heavy_overlap(self) -> bool:
        es = [r for r, _ in self.entries]
        return all(_overlap(r1, r2) for r1 in es for r2 in es)
    def query(self, rect: Rect) -> List[object]:
        out = [p for r, p in self.entries if _overlap(r, rect)]
        for ch in self.children:
            out.extend(ch.query(rect))
        return out

def main() -> None:
    x = XTreeMock(cap=2)
    for i in range(6):
        x.insert((0, 0, 5, 5), i)  # heavy overlap -> supernode
    assert x.supernode is True
    assert sorted(x.query((1, 1, 2, 2))) == [0, 1, 2, 3, 4, 5]
    print("tree_28 X-tree (mock) OK")

if __name__ == "__main__":
    main()
