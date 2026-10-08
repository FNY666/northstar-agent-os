"""Verify a complete binary tree via level-order gap detection. Stdlib only."""
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


def is_complete(root: Optional[Node]) -> bool:
    if root is None: return True
    q, end = deque([root]), False
    while q:
        n = q.popleft()
        if n is None:
            end = True
        else:
            if end: return False
            q.append(n.left); q.append(n.right)
    return True

def complete_sample() -> Node:
    r = Node(1); r.left = Node(2); r.right = Node(3)
    r.left.left = Node(4); r.left.right = Node(5); r.right.left = Node(6)
    return r


def main() -> None:
    assert is_complete(complete_sample()) is True
    assert is_complete(sample()) is False
    assert is_complete(None) is True
    r = Node(1); r.left = Node(2); r.left.left = Node(3); assert is_complete(r) is False
    print("trav_40 OK")


if __name__ == "__main__":
    main()
