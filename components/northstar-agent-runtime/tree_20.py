"""R-tree (mock): MBR-based 2D rectangle index. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

Rect = Tuple[float, float, float, float]  # x0, y0, x1, y1

def _area(r: Rect) -> float:
    return max(0.0, r[2] - r[0]) * max(0.0, r[3] - r[1])

def _combine(a: Rect, b: Rect) -> Rect:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))

def _overlap(a: Rect, b: Rect) -> bool:
    return a[0] <= b[2] and a[2] >= b[0] and a[1] <= b[3] and a[3] >= b[1]

class RNode:
    def __init__(self, leaf: bool = True, cap: int = 4) -> None:
        self.leaf = leaf
        self.cap = cap
        self.entries: List[Tuple[Rect, object]] = []  # rect, child-or-payload
        self.mbr: Rect | None = None
    def _refresh(self) -> None:
        m = None
        for r, _ in self.entries: m = r if m is None else _combine(m, r)
        self.mbr = m

class RTreeMock:
    def __init__(self, cap: int = 4) -> None:
        self.root = RNode(leaf=True, cap=cap)
    def _choose_leaf(self, node: RNode, rect: Rect) -> RNode:
        while not node.leaf:
            best, be = None, None
            for r, child in node.entries:
                enl = _area(_combine(r, rect)) - _area(r)
                if be is None or enl < be:
                    best, be = child, enl
            node = best
        return node
    def insert(self, rect: Rect, payload: object) -> None:
        leaf = self._choose_leaf(self.root, rect)
        leaf.entries.append((rect, payload))
        leaf._refresh()
        if leaf is self.root and len(leaf.entries) > leaf.cap:
            self._split_root()
    def _split_root(self) -> None:
        old = self.root
        mid = len(old.entries) // 2
        a, b = RNode(leaf=True, cap=old.cap), RNode(leaf=True, cap=old.cap)
        a.entries = old.entries[:mid]; b.entries = old.entries[mid:]
        a._refresh(); b._refresh()
        self.root = RNode(leaf=False, cap=old.cap)
        self.root.entries = [(a.mbr, a), (b.mbr, b)]
        self.root._refresh()
    def query(self, rect: Rect) -> List[object]:
        out: List[object] = []
        def rec(node):
            for r, child in node.entries:
                if _overlap(r, rect):
                    if node.leaf: out.append(child)
                    else: rec(child)
        rec(self.root)
        return out

def main() -> None:
    rt = RTreeMock(cap=2)
    rt.insert((0, 0, 2, 2), "a")
    rt.insert((3, 3, 5, 5), "b")
    rt.insert((1, 1, 4, 4), "c")
    assert sorted(rt.query((0, 0, 0.5, 0.5))) == ["a"]
    assert sorted(rt.query((0, 0, 10, 10))) == ["a", "b", "c"]
    assert rt.query((6, 6, 7, 7)) == []
    print("tree_20 R-tree (mock) OK")

if __name__ == "__main__":
    main()
