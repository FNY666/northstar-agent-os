"""Preorder traversal limited to a maximum depth. Stdlib only."""
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


def preorder_depth_limited(root: Optional[Node], max_depth: int) -> List[int]:
    out: List[int] = []
    def walk(n, d):
        if n is None or d > max_depth: return
        out.append(n.val); walk(n.left, d + 1); walk(n.right, d + 1)
    walk(root, 0); return out

def main() -> None:
    assert preorder_depth_limited(sample(), 0) == [1]
    assert preorder_depth_limited(sample(), 1) == [1, 2, 3]
    assert preorder_depth_limited(sample(), 9) == [1, 2, 4, 5, 3, 6]
    assert preorder_depth_limited(None, 2) == []
    print("trav_26 OK")


if __name__ == "__main__":
    main()
