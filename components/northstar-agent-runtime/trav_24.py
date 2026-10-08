"""Inorder as a lazy generator; kth smallest element. Stdlib only."""
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


def inorder_gen(root: Optional[Node]):
    st, cur = [], root
    while st or cur:
        while cur:
            st.append(cur); cur = cur.left
        cur = st.pop(); yield cur.val; cur = cur.right
def kth_smallest(root: Optional[Node], k: int) -> Optional[int]:
    for i, v in enumerate(inorder_gen(root), 1):
        if i == k: return v
    return None

def main() -> None:
    assert list(inorder_gen(sample())) == [4, 2, 5, 1, 3, 6]
    assert kth_smallest(sample(), 1) == 4
    assert kth_smallest(sample(), 3) == 5
    assert kth_smallest(None, 1) is None
    print("trav_24 OK")


if __name__ == "__main__":
    main()
