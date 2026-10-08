"""Morris preorder traversal (O(1) extra space). Stdlib only."""
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


def morris_preorder(root: Optional[Node]) -> List[int]:
    out, cur = [], root
    while cur:
        if cur.left is None:
            out.append(cur.val); cur = cur.right
        else:
            pre = cur.left
            while pre.right and pre.right is not cur:
                pre = pre.right
            if pre.right is None:
                out.append(cur.val); pre.right = cur; cur = cur.left
            else:
                pre.right = None; cur = cur.right
    return out

def main() -> None:
    assert morris_preorder(sample()) == [1, 2, 4, 5, 3, 6]
    assert morris_preorder(None) == []
    t = sample(); assert morris_preorder(t) == [1, 2, 4, 5, 3, 6] and t.left.left.right is None and t.left.right.right is None
    print("trav_13 OK")


if __name__ == "__main__":
    main()
