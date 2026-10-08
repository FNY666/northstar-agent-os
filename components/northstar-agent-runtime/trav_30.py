"""Postorder accumulation of subtree sums. Stdlib only."""
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


def subtree_sums(root: Optional[Node]) -> dict:
    sums: dict = {}
    def walk(n):
        if n is None: return 0
        s = n.val + walk(n.left) + walk(n.right)
        sums[n.val] = s
        return s
    walk(root); return sums

def main() -> None:
    assert subtree_sums(sample()) == {4: 4, 5: 5, 2: 11, 6: 6, 3: 9, 1: 21}
    assert subtree_sums(None) == {}
    assert subtree_sums(Node(5)) == {5: 5}
    print("trav_30 OK")


if __name__ == "__main__":
    main()
