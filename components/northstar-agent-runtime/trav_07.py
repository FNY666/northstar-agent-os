"""Postorder iterative traversal using two stacks. Stdlib only."""
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


def postorder_two_stacks(root: Optional[Node]) -> List[int]:
    if root is None: return []
    s1, s2 = [root], []
    while s1:
        n = s1.pop(); s2.append(n)
        if n.left: s1.append(n.left)
        if n.right: s1.append(n.right)
    return [n.val for n in reversed(s2)]

def main() -> None:
    assert postorder_two_stacks(sample()) == [4, 5, 2, 6, 3, 1]
    assert postorder_two_stacks(None) == []
    assert postorder_two_stacks(Node(4)) == [4]
    print("trav_07 OK")


if __name__ == "__main__":
    main()
