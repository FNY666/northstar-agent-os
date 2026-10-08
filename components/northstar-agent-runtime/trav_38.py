"""Preorder of the mirrored tree (right before left). Stdlib only."""
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


def mirror_preorder(root: Optional[Node]) -> List[int]:
    out: List[int] = []
    def walk(n):
        if n is None: return
        out.append(n.val); walk(n.right); walk(n.left)
    walk(root); return out

def main() -> None:
    assert mirror_preorder(sample()) == [1, 3, 6, 2, 5, 4]
    assert mirror_preorder(None) == []
    assert mirror_preorder(Node(2)) == [2]
    print("trav_38 OK")


if __name__ == "__main__":
    main()
