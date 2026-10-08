"""Verify a perfect binary tree via level-order counting. Stdlib only."""
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


def is_perfect(root: Optional[Node]) -> bool:
    if root is None: return True
    q, expect = deque([root]), 1
    while q:
        if len(q) != expect: return False
        nxt = []
        for n in q:
            if (n.left is None) != (n.right is None): return False
            if n.left: nxt += [n.left, n.right]
        if not nxt: return True
        q, expect = deque(nxt), expect * 2
    return True
def perfect() -> Node:
    r = Node(1); r.left = Node(2); r.right = Node(3)
    r.left.left = Node(4); r.left.right = Node(5)
    r.right.left = Node(6); r.right.right = Node(7)
    return r

def main() -> None:
    assert is_perfect(perfect()) is True
    assert is_perfect(sample()) is False
    assert is_perfect(None) is True
    print("trav_39 OK")


if __name__ == "__main__":
    main()
