"""Boundary traversal: root, left edge, leaves, right edge reversed. Stdlib only."""
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


def _is_leaf(n): return n.left is None and n.right is None
def _leaves(n, out):
    if n is None: return
    if _is_leaf(n): out.append(n.val); return
    _leaves(n.left, out); _leaves(n.right, out)
def boundary(root: Optional[Node]) -> List[int]:
    if root is None: return []
    if _is_leaf(root): return [root.val]
    out = [root.val]
    n = root.left
    while n and not _is_leaf(n):
        out.append(n.val); n = n.left if n.left else n.right
    _leaves(root, out)
    right_edge = []
    n = root.right
    while n and not _is_leaf(n):
        right_edge.append(n.val); n = n.right if n.right else n.left
    out.extend(reversed(right_edge))
    return out

def main() -> None:
    assert boundary(sample()) == [1, 2, 4, 5, 6, 3]
    assert boundary(None) == []
    assert boundary(Node(1)) == [1]
    print("trav_14 OK")


if __name__ == "__main__":
    main()
