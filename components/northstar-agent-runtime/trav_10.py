"""Reverse level-order traversal (bottom-up, left-to-right). Stdlib only."""
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


def reverse_level(root: Optional[Node]) -> List[int]:
    if root is None: return []
    out, q, st = [], deque([root]), []
    while q:
        n = q.popleft(); st.append(n.val)
        if n.right: q.append(n.right)
        if n.left: q.append(n.left)
    while st: out.append(st.pop())
    return out

def main() -> None:
    assert reverse_level(sample()) == [4, 5, 6, 2, 3, 1]
    assert reverse_level(None) == []
    assert reverse_level(Node(9)) == [9]
    print("trav_10 OK")


if __name__ == "__main__":
    main()
