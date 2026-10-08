"""Postorder iterative traversal using a single stack. Stdlib only."""
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


def postorder_one_stack(root: Optional[Node]) -> List[int]:
    out, st, last = [], [], None
    cur = root
    while st or cur:
        if cur:
            st.append(cur); cur = cur.left
        else:
            peek = st[-1]
            if peek.right and last is not peek.right:
                cur = peek.right
            else:
                out.append(peek.val); last = st.pop()
    return out

def main() -> None:
    assert postorder_one_stack(sample()) == [4, 5, 2, 6, 3, 1]
    assert postorder_one_stack(None) == []
    assert postorder_one_stack(Node(6)) == [6]
    print("trav_08 OK")


if __name__ == "__main__":
    main()
