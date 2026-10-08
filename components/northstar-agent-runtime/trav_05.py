"""Preorder iterative traversal using an explicit stack. Stdlib only."""
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


def preorder_iter(root: Optional[Node]) -> List[int]:
    if root is None: return []
    out, st = [], [root]
    while st:
        n = st.pop(); out.append(n.val)
        if n.right: st.append(n.right)
        if n.left: st.append(n.left)
    return out

def main() -> None:
    assert preorder_iter(sample()) == [1, 2, 4, 5, 3, 6]
    assert preorder_iter(None) == []
    assert preorder_iter(Node(3)) == [3]
    print("trav_05 OK")


if __name__ == "__main__":
    main()
