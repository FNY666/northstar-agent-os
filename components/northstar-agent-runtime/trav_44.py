"""Minimum depth (nearest leaf) via BFS early exit. Stdlib only."""
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


def min_depth(root: Optional[Node]) -> int:
    if root is None: return 0
    d, q = 0, deque([root])
    while q:
        d += 1
        for _ in range(len(q)):
            n = q.popleft()
            if n.left is None and n.right is None: return d
            if n.left: q.append(n.left)
            if n.right: q.append(n.right)
    return d

def main() -> None:
    assert min_depth(sample()) == 3
    assert min_depth(None) == 0
    r = Node(1); r.left = Node(2); assert min_depth(r) == 2
    print("trav_44 OK")


if __name__ == "__main__":
    main()
