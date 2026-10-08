"""Vertical-order traversal grouped by horizontal distance. Stdlib only."""
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


def vertical_order(root: Optional[Node]) -> List[List[int]]:
    if root is None: return []
    cols: dict = {}
    q = deque([(root, 0)])
    while q:
        n, d = q.popleft()
        cols.setdefault(d, []).append(n.val)
        if n.left: q.append((n.left, d - 1))
        if n.right: q.append((n.right, d + 1))
    return [cols[d] for d in sorted(cols)]

def main() -> None:
    assert vertical_order(sample()) == [[4], [2], [1, 5], [3], [6]]
    assert vertical_order(None) == []
    assert vertical_order(Node(1)) == [[1]]
    print("trav_15 OK")


if __name__ == "__main__":
    main()
