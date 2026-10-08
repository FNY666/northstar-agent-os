"""B-tree (order m, mock): insert with node splits. Stdlib only."""
from __future__ import annotations
from typing import List

class BNode:
    def __init__(self, leaf: bool = True) -> None:
        self.keys: List[int] = []
        self.children: List["BNode"] = []
        self.leaf = leaf

class BTree:
    def __init__(self, m: int = 3) -> None:
        assert m >= 3
        self.m = m
        self.t = (m + 1) // 2  # min degree
        self.root = BNode(leaf=True)
    def search(self, key: int, node: BNode | None = None) -> bool:
        node = node or self.root
        i = 0
        while i < len(node.keys) and key > node.keys[i]: i += 1
        if i < len(node.keys) and key == node.keys[i]: return True
        if node.leaf: return False
        return self.search(key, node.children[i])
    def insert(self, key: int) -> None:
        r = self.root
        if len(r.keys) == 2 * self.t - 1:
            s = BNode(leaf=False)
            s.children.append(r)
            self.root = s
            self._split(s, 0)
            self._insert_nonfull(s, key)
        else:
            self._insert_nonfull(r, key)
    def _split(self, parent: BNode, i: int) -> None:
        t = self.t
        y = parent.children[i]
        z = BNode(leaf=y.leaf)
        mid = y.keys[t - 1]
        z.keys = y.keys[t:]
        y.keys = y.keys[:t - 1]
        if not y.leaf:
            z.children = y.children[t:]
            y.children = y.children[:t]
        parent.children.insert(i + 1, z)
        parent.keys.insert(i, mid)
    def _insert_nonfull(self, node: BNode, key: int) -> None:
        i = len(node.keys) - 1
        if node.leaf:
            node.keys.append(0)
            while i >= 0 and key < node.keys[i]:
                node.keys[i + 1] = node.keys[i]; i -= 1
            node.keys[i + 1] = key
        else:
            while i >= 0 and key < node.keys[i]: i -= 1
            i += 1
            if len(node.children[i].keys) == 2 * self.t - 1:
                self._split(node, i)
                if key > node.keys[i]: i += 1
            self._insert_nonfull(node.children[i], key)
    def keys_sorted(self) -> List[int]:
        out: List[int] = []
        def rec(n):
            for i, k in enumerate(n.keys):
                if not n.leaf: rec(n.children[i])
                out.append(k)
            if not n.leaf: rec(n.children[-1])
        rec(self.root); return out

def main() -> None:
    bt = BTree(m=3)
    for k in [10, 20, 5, 6, 12, 30, 7, 17]: bt.insert(k)
    assert bt.keys_sorted() == [5, 6, 7, 10, 12, 17, 20, 30]
    assert bt.search(12) and not bt.search(99)
    assert len(bt.root.keys) <= 2
    print("tree_04 B-tree (mock) OK")

if __name__ == "__main__":
    main()
