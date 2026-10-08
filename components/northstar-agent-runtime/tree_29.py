"""SS-tree (mock): similarity search with spherical MBRs. Stdlib only."""
from __future__ import annotations
import math
from typing import List, Tuple

def _dist(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

def _centroid(pts):
    n = len(pts)
    return tuple(sum(p[i] for p in pts) / n for i in range(len(pts[0])))

class SSNode:
    def __init__(self, leaf: bool = True, cap: int = 4) -> None:
        self.leaf = leaf
        self.cap = cap
        self.center = None
        self.radius = 0.0
        self.entries: List[tuple] = []  # points or child nodes

class SSTreeMock:
    def __init__(self, cap: int = 4) -> None:
        self.root = SSNode(leaf=True, cap=cap)
    def insert(self, p: tuple) -> None:
        node = self.root
        while not node.leaf:
            node = min(node.entries, key=lambda ch: _dist(p, ch.center))
        node.entries.append(p)
        self._refresh(node)
        if node is self.root and len(node.entries) > node.cap:
            self._split_root()
        self._refresh(self.root)
    def _refresh(self, n: SSNode) -> None:
        if n.leaf:
            n.center = _centroid(n.entries)
            n.radius = max(_dist(n.center, p) for p in n.entries)
        else:
            n.center = _centroid([ch.center for ch in n.entries])
            n.radius = max(_dist(n.center, ch.center) + ch.radius for ch in n.entries)
    def _split_root(self) -> None:
        old = self.root
        mid = len(old.entries) // 2
        a, b = SSNode(True, old.cap), SSNode(True, old.cap)
        a.entries, b.entries = old.entries[:mid], old.entries[mid:]
        self._refresh(a); self._refresh(b)
        self.root = SSNode(leaf=False, cap=old.cap)
        self.root.entries = [a, b]
        self._refresh(self.root)
    def nn(self, q: tuple):
        best, bd = None, float("inf")
        def rec(n):
            nonlocal best, bd
            if _dist(q, n.center) - n.radius >= bd: return
            if n.leaf:
                for p in n.entries:
                    d = _dist(q, p)
                    if d < bd: best, bd = p, d
            else:
                for c in sorted(n.entries, key=lambda c: _dist(q, c.center)):
                    rec(c)
        rec(self.root)
        return best

def main() -> None:
    ss = SSTreeMock(cap=2)
    for p in [(0, 0), (1, 1), (9, 9), (8, 8)]: ss.insert(p)
    assert ss.nn((0.5, 0.5)) in ((0, 0), (1, 1))
    assert ss.nn((8.5, 8.5)) in ((8, 8), (9, 9))
    assert ss.root.center is not None
    print("tree_29 SS-tree (mock) OK")

if __name__ == "__main__":
    main()
