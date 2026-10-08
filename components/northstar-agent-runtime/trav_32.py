"""Inorder traversal filtered to a key range [lo, hi]. Stdlib only."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Node:
    val: int
    left: Optional["Node"] = None
    right: Optional["Node"] = None
    kids: List["Node"] = field(default_factory=list)  # for n-ary variants


def sample() -> Node:
    """Sample tree:
            1
           / \\
          2   3
         / \\   \\
        4   5   6
    """
    n1, n2, n3 = Node(1), Node(2), Node(3)
    n4, n5, n6 = Node(4), Node(5), Node(6)
    n1.left, n1.right = n2, n3
    n2.left, n2.right = n4, n5
    n3.right = n6
    return n1


def inorder_range(root: Optional[Node], lo: int, hi: int) -> List[int]:
    out: List[int] = []
    def walk(n):
        if n is None: return
        if n.val > lo: walk(n.left)
        if lo <= n.val <= hi: out.append(n.val)
        if n.val < hi: walk(n.right)
    walk(root); return out
def bst_sample() -> Node:
    r = Node(4); r.left = Node(2); r.right = Node(6)
    r.left.left = Node(1); r.left.right = Node(3); r.right.right = Node(7)
    return r

def main() -> None:
    assert inorder_range(bst_sample(), 2, 6) == [2, 3, 4, 6]
    assert inorder_range(bst_sample(), 8, 9) == []
    assert inorder_range(None, 0, 9) == []
    print("trav_32 OK")


if __name__ == "__main__":
    main()
