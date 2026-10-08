"""Zigzag (spiral) level-order traversal. Stdlib only."""
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


def zigzag(root: Optional[Node]) -> List[int]:
    if root is None: return []
    out, level, ltr = [], [root], True
    while level:
        out.extend(n.val for n in (level if ltr else reversed(level)))
        nxt = []
        for n in level:
            if n.left: nxt.append(n.left)
            if n.right: nxt.append(n.right)
        level, ltr = nxt, not ltr
    return out

def main() -> None:
    assert zigzag(sample()) == [1, 3, 2, 4, 5, 6]
    assert zigzag(None) == []
    assert zigzag(Node(1)) == [1]
    print("trav_09 OK")


if __name__ == "__main__":
    main()
