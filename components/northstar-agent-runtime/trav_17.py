"""Bottom view: last node seen at each horizontal distance. Stdlib only."""
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


def bottom_view(root: Optional[Node]) -> List[int]:
    if root is None: return []
    seen: dict = {}
    q = deque([(root, 0)])
    while q:
        n, d = q.popleft()
        seen[d] = n.val
        if n.left: q.append((n.left, d - 1))
        if n.right: q.append((n.right, d + 1))
    return [seen[d] for d in sorted(seen)]

def main() -> None:
    assert bottom_view(sample()) == [4, 2, 5, 3, 6]
    assert bottom_view(None) == []
    assert bottom_view(Node(7)) == [7]
    print("trav_17 OK")


if __name__ == "__main__":
    main()
