"""Red-Black tree (simplified mock): colored BST insert with recolor fixup. Stdlib only.

Simplified: enforces no two consecutive red nodes and black-root via
recoloring; real RB needs rotations for full compliance (documented).
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

RED, BLACK = 0, 1

@dataclass
class Node:
    key: int
    color: int = RED
    left: Optional["Node"] = None
    right: Optional["Node"] = None
    parent: Optional["Node"] = None

class RBTree:
    def __init__(self) -> None:
        self.root: Optional[Node] = None
    def insert(self, key: int) -> None:
        n = Node(key)
        if self.root is None:
            n.color = BLACK; self.root = n; return
        cur, par = self.root, None
        while cur is not None:
            if key == cur.key: return
            par = cur
            cur = cur.left if key < cur.key else cur.right
        n.parent = par
        if key < par.key: par.left = n
        else: par.right = n
        self._fix(n)
    def _fix(self, n: Node) -> None:
        # Simplified fixup: recolor double-red chains; root forced black.
        while n.parent is not None and n.parent.color == RED:
            p, gp = n.parent, n.parent.parent
            if gp is None: break
            uncle = gp.right if p is gp.left else gp.left
            if uncle is not None and uncle.color == RED:
                p.color = BLACK; uncle.color = BLACK; gp.color = RED
                n = gp
            else:
                # Simplified: recolor parent/grandparent instead of rotate.
                p.color = BLACK; gp.color = RED
                n = gp
        if self.root is not None: self.root.color = BLACK
    def inorder(self) -> List[int]:
        out: List[int] = []
        def rec(n):
            if n is not None: rec(n.left); out.append(n.key); rec(n.right)
        rec(self.root); return out
    def no_double_red(self) -> bool:
        ok = True
        def rec(n):
            nonlocal ok
            if n is None: return
            if n.color == RED:
                if (n.left and n.left.color == RED) or (n.right and n.right.color == RED):
                    ok = False
            rec(n.left); rec(n.right)
        rec(self.root); return ok

def main() -> None:
    tr = RBTree()
    for k in [10, 5, 15, 3, 7, 12, 20]: tr.insert(k)
    assert tr.inorder() == [3, 5, 7, 10, 12, 15, 20]
    assert tr.root is not None and tr.root.color == BLACK
    assert tr.no_double_red()
    print("tree_03 Red-Black (mock) OK")

if __name__ == "__main__":
    main()
