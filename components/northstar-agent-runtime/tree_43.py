"""K-ary tree: level-order insert, BFS, height. Stdlib only."""
from __future__ import annotations
from collections import deque
from typing import List

class KNode:
    def __init__(self, val: int) -> None:
        self.val = val
        self.children: List["KNode"] = []

class KaryTree:
    def __init__(self, k: int) -> None:
        assert k >= 2
        self.k = k
        self.root = None
    def insert(self, val: int) -> None:
        node = KNode(val)
        if self.root is None:
            self.root = node; return
        q = deque([self.root])
        while q:
            cur = q.popleft()
            if len(cur.children) < self.k:
                cur.children.append(node); return
            q.extend(cur.children)
    def bfs(self) -> List[int]:
        if self.root is None: return []
        out, q = [], deque([self.root])
        while q:
            cur = q.popleft(); out.append(cur.val); q.extend(cur.children)
        return out
    def height(self) -> int:
        def h(n): return 0 if n is None else 1 + max([h(c) for c in n.children] or [0])
        return h(self.root)

def main() -> None:
    t = KaryTree(3)
    for v in range(1, 8): t.insert(v)
    assert t.bfs() == [1, 2, 3, 4, 5, 6, 7]
    assert t.height() == 3
    assert KaryTree(2).height() == 0
    print("tree_43 K-ary tree OK")

if __name__ == "__main__":
    main()
