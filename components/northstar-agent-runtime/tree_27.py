"""M-tree (mock): metric routing tree with covering radii. Stdlib only."""
from __future__ import annotations
import math
from typing import List, Optional, Tuple

def _dist(a, b) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

class MNode:
    def __init__(self, leaf: bool = True, cap: int = 4) -> None:
        self.leaf = leaf
        self.cap = cap
        self.entries: List[Tuple[tuple, float, object]] = []  # obj, radius, child/payload
        self.rep: Optional[tuple] = None

class MTreeMock:
    def __init__(self, cap: int = 4) -> None:
        self.root = MNode(leaf=True, cap=cap)
    def _leaf_for(self, obj: tuple) -> MNode:
        node = self.root
        while not node.leaf:
            node = min(node.entries, key=lambda e: _dist(obj, e[0]))[2]
        return node
    def insert(self, obj: tuple, payload: object) -> None:
        leaf = self._leaf_for(obj)
        leaf.entries.append((obj, 0.0, payload))
        if leaf.rep is None: leaf.rep = obj
        if leaf is self.root and len(leaf.entries) > leaf.cap:
            self._split_root()
        self._refresh_up()
    def _refresh_up(self) -> None:
        def rec(node):
            if node.leaf:
                node.entries = [(o, 0.0, p) for o, _, p in node.entries]
            else:
                for _, _, ch in node.entries: rec(ch)
                node.entries = [
                    (ch.rep,
                     max((_dist(ch.rep, o) for o, _, _ in ch.entries), default=0.0),
                     ch)
                    for _, _, ch in node.entries
                ]
        rec(self.root)
    def _split_root(self) -> None:
        old = self.root
        mid = len(old.entries) // 2
        left, right = MNode(True, old.cap), MNode(True, old.cap)
        left.entries = old.entries[:mid]; right.entries = old.entries[mid:]
        left.rep = left.entries[0][0]; right.rep = right.entries[0][0]
        self.root = MNode(leaf=False, cap=old.cap)
        self.root.entries = [(left.rep, 0.0, left), (right.rep, 0.0, right)]
    def range_query(self, q: tuple, radius: float) -> List[object]:
        out: List[object] = []
        def rec(node):
            for obj, r, child in node.entries:
                if _dist(q, obj) <= radius + r:
                    if node.leaf: out.append(child)
                    else: rec(child)
        rec(self.root)
        return out

def main() -> None:
    mt = MTreeMock(cap=2)
    for i, p in enumerate([(0, 0), (1, 0), (10, 10), (11, 10)]):
        mt.insert(p, i)
    got = sorted(mt.range_query((0, 0), 2.0))
    assert got == [0, 1]
    assert mt.range_query((50, 50), 1.0) == []
    print("tree_27 M-tree (mock) OK")

if __name__ == "__main__":
    main()
