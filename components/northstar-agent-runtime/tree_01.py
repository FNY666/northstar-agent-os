"""Binary Search Tree (BST): insert, search, delete, inorder, height. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Node:
    key: int
    left: Optional["Node"] = None
    right: Optional["Node"] = None

class BST:
    def __init__(self) -> None:
        self.root: Optional[Node] = None
        self.size = 0
    def insert(self, key: int) -> None:
        if self.root is None:
            self.root = Node(key); self.size += 1; return
        cur = self.root
        while True:
            if key == cur.key: return
            if key < cur.key:
                if cur.left is None: cur.left = Node(key); self.size += 1; return
                cur = cur.left
            else:
                if cur.right is None: cur.right = Node(key); self.size += 1; return
                cur = cur.right
    def search(self, key: int) -> bool:
        cur = self.root
        while cur is not None:
            if key == cur.key: return True
            cur = cur.left if key < cur.key else cur.right
        return False
    def delete(self, key: int) -> bool:
        self.root, deleted = self._delete(self.root, key)
        if deleted: self.size -= 1
        return deleted
    def _delete(self, node, key):
        if node is None: return None, False
        if key < node.key:
            node.left, d = self._delete(node.left, key); return node, d
        if key > node.key:
            node.right, d = self._delete(node.right, key); return node, d
        if node.left is None: return node.right, True
        if node.right is None: return node.left, True
        succ = node.right
        while succ.left is not None: succ = succ.left
        node.key = succ.key
        node.right, _ = self._delete(node.right, succ.key)
        return node, True
    def inorder(self) -> List[int]:
        out: List[int] = []
        def rec(n):
            if n is not None: rec(n.left); out.append(n.key); rec(n.right)
        rec(self.root); return out
    def height(self) -> int:
        def h(n): return 0 if n is None else 1 + max(h(n.left), h(n.right))
        return h(self.root)

def main() -> None:
    t = BST()
    for k in [5, 3, 7, 2, 4, 6, 8]: t.insert(k)
    assert t.inorder() == [2, 3, 4, 5, 6, 7, 8]
    assert t.size == 7
    assert t.search(4) and not t.search(9)
    assert t.delete(3) and t.inorder() == [2, 4, 5, 6, 7, 8]
    assert not t.delete(42)
    assert t.height() >= 3
    print("tree_01 BST OK")

if __name__ == "__main__":
    main()
