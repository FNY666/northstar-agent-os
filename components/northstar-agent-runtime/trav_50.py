"""Cousin test: same depth, different parents via BFS. Stdlib only."""
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


def are_cousins(root: Optional[Node], a: int, b: int) -> bool:
    if root is None or a == b: return False
    q = deque([(root, None, 0)])
    info = {}
    while q:
        n, par, d = q.popleft()
        if n.val == a or n.val == b:
            info[n.val] = (par, d)
            if len(info) == 2: break
        if n.left: q.append((n.left, n, d + 1))
        if n.right: q.append((n.right, n, d + 1))
    if a not in info or b not in info: return False
    (pa, da), (pb, db) = info[a], info[b]
    return da == db and pa is not pb

def main() -> None:
    assert are_cousins(sample(), 4, 6) is True
    assert are_cousins(sample(), 4, 5) is False
    assert are_cousins(sample(), 2, 3) is False
    print("trav_50 OK")


if __name__ == "__main__":
    main()
