"""Sum all node values with iterative DFS. Stdlib only."""
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


def tree_sum(root: Optional[Node]) -> int:
    if root is None: return 0
    s, st = 0, [root]
    while st:
        n = st.pop(); s += n.val
        if n.left: st.append(n.left)
        if n.right: st.append(n.right)
    return s

def main() -> None:
    assert tree_sum(sample()) == 21
    assert tree_sum(None) == 0
    assert tree_sum(Node(7)) == 7
    print("trav_46 OK")


if __name__ == "__main__":
    main()
