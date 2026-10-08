"""Check tree symmetry by comparing mirrored traversals. Stdlib only."""
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


def is_symmetric(root: Optional[Node]) -> bool:
    def walk(a, b):
        if a is None and b is None: return True
        if a is None or b is None or a.val != b.val: return False
        return walk(a.left, b.right) and walk(a.right, b.left)
    return root is None or walk(root.left, root.right)
def sym() -> Node:
    r = Node(1); r.left = Node(2); r.right = Node(2)
    r.left.left = Node(3); r.right.right = Node(3)
    return r

def main() -> None:
    assert is_symmetric(sym()) is True
    assert is_symmetric(sample()) is False
    assert is_symmetric(None) is True
    print("trav_41 OK")


if __name__ == "__main__":
    main()
