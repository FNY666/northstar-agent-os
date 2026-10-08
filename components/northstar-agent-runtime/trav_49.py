"""Lowest common ancestor by root-to-node path comparison. Stdlib only."""
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


def _path(root, target, path):
    if root is None: return None
    path = path + [root]
    if root.val == target: return path
    return _path(root.left, target, path) or _path(root.right, target, path)
def lca(root: Optional[Node], a: int, b: int) -> Optional[int]:
    pa, pb = _path(root, a, []), _path(root, b, [])
    if pa is None or pb is None: return None
    anc = None
    for x, y in zip(pa, pb):
        if x.val != y.val: break
        anc = x.val
    return anc

def main() -> None:
    assert lca(sample(), 4, 5) == 2
    assert lca(sample(), 4, 6) == 1
    assert lca(sample(), 4, 99) is None
    print("trav_49 OK")


if __name__ == "__main__":
    main()
