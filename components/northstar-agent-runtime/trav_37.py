"""Zigzag traversal using two stacks instead of reversal. Stdlib only."""
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


def zigzag_stacks(root: Optional[Node]) -> List[int]:
    if root is None: return []
    out, cur, nxt, ltr = [], [root], [], True
    while cur:
        n = cur.pop(); out.append(n.val)
        kids = (n.left, n.right) if ltr else (n.right, n.left)
        for k in kids:
            if k: nxt.append(k)
        if not cur:
            cur, nxt, ltr = nxt, [], not ltr
    return out

def main() -> None:
    assert zigzag_stacks(sample()) == [1, 3, 2, 4, 5, 6]
    assert zigzag_stacks(None) == []
    assert zigzag_stacks(Node(1)) == [1]
    print("trav_37 OK")


if __name__ == "__main__":
    main()
