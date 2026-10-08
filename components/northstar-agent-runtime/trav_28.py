"""Enumerate all root-to-leaf paths. Stdlib only."""
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


def root_to_leaf_paths(root: Optional[Node]) -> List[List[int]]:
    out: List[List[int]] = []
    def walk(n, path):
        if n is None: return
        path = path + [n.val]
        if n.left is None and n.right is None:
            out.append(path); return
        walk(n.left, path); walk(n.right, path)
    walk(root, []); return out

def main() -> None:
    assert root_to_leaf_paths(sample()) == [[1, 2, 4], [1, 2, 5], [1, 3, 6]]
    assert root_to_leaf_paths(None) == []
    assert root_to_leaf_paths(Node(1)) == [[1]]
    print("trav_28 OK")


if __name__ == "__main__":
    main()
