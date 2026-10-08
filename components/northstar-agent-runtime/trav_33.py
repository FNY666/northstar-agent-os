"""Preorder with predicate-based subtree pruning. Stdlib only."""
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


def preorder_prune(root: Optional[Node], skip) -> List[int]:
    out: List[int] = []
    def walk(n):
        if n is None or skip(n): return
        out.append(n.val); walk(n.left); walk(n.right)
    walk(root); return out

def main() -> None:
    assert preorder_prune(sample(), lambda n: n.val == 2) == [1, 3, 6]
    assert preorder_prune(sample(), lambda n: False) == [1, 2, 4, 5, 3, 6]
    assert preorder_prune(None, lambda n: False) == []
    print("trav_33 OK")


if __name__ == "__main__":
    main()
