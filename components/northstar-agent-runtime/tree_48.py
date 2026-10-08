"""T-tree (mock): BST nodes holding sorted arrays. Stdlib only."""
from __future__ import annotations
from bisect import bisect_left
from typing import List, Optional

CAP = 4

class TNode:
    def __init__(self) -> None:
        self.keys: List[int] = []
        self.left: Optional["TNode"] = None
        self.right: Optional["TNode"] = None
    @property
    def lo(self): return self.keys[0]
    @property
    def hi(self): return self.keys[-1]

class TTreeMock:
    def __init__(self) -> None:
        self.root: Optional[TNode] = None
    def insert(self, key: int) -> None:
        self.root = self._ins(self.root, key)
    def _ins(self, n, key):
        if n is None:
            n = TNode(); n.keys = [key]; return n
        if n.lo <= key <= n.hi or len(n.keys) < CAP:
            if key not in n.keys:
                i = bisect_left(n.keys, key)
                if n.lo <= key <= n.hi or len(n.keys) < CAP:
                    n.keys.insert(i, key); return n
        if key < n.lo: n.left = self._ins(n.left, key)
        else: n.right = self._ins(n.right, key)
        return n
    def search(self, key: int) -> bool:
        n = self.root
        while n is not None:
            i = bisect_left(n.keys, key)
            if i < len(n.keys) and n.keys[i] == key: return True
            n = n.left if key < n.lo else n.right
        return False
    def inorder(self) -> List[int]:
        out: List[int] = []
        def rec(n):
            if n is not None: rec(n.left); out.extend(n.keys); rec(n.right)
        rec(self.root); return out

def main() -> None:
    t = TTreeMock()
    for k in [5, 3, 7, 1, 9, 2, 8]: t.insert(k)
    assert t.inorder() == [1, 2, 3, 5, 7, 8, 9]
    assert t.search(8) and not t.search(6)
    print("tree_48 T-tree (mock) OK")

if __name__ == "__main__":
    main()
