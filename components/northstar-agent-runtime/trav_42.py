"""Compare two trees for structural and value equality. Stdlib only."""
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


def same_tree(a: Optional[Node], b: Optional[Node]) -> bool:
    if a is None and b is None: return True
    if a is None or b is None or a.val != b.val: return False
    return same_tree(a.left, b.left) and same_tree(a.right, b.right)

def main() -> None:
    assert same_tree(sample(), sample()) is True
    assert same_tree(sample(), None) is False
    assert same_tree(None, None) is True
    print("trav_42 OK")


if __name__ == "__main__":
    main()
