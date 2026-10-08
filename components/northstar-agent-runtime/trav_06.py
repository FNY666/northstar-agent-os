"""Inorder iterative traversal using an explicit stack. Stdlib only."""
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


def inorder_iter(root: Optional[Node]) -> List[int]:
    out, st, cur = [], [], root
    while st or cur:
        while cur:
            st.append(cur); cur = cur.left
        cur = st.pop(); out.append(cur.val); cur = cur.right
    return out

def main() -> None:
    assert inorder_iter(sample()) == [4, 2, 5, 1, 3, 6]
    assert inorder_iter(None) == []
    assert inorder_iter(Node(2)) == [2]
    print("trav_06 OK")


if __name__ == "__main__":
    main()
