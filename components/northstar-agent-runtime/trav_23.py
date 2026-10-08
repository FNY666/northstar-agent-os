"""N-ary tree level-order traversal via kids list. Stdlib only."""
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


def nary_level(root: Optional[Node]) -> List[int]:
    if root is None: return []
    out, q = [], deque([root])
    while q:
        n = q.popleft(); out.append(n.val)
        q.extend(n.kids)
    return out
def nary_sample() -> Node:
    r = Node(1); a, b = Node(2), Node(3); c = Node(4)
    r.kids = [a, b]; a.kids = [c]
    return r

def main() -> None:
    assert nary_level(nary_sample()) == [1, 2, 3, 4]
    assert nary_level(None) == []
    assert nary_level(Node(9)) == [9]
    print("trav_23 OK")


if __name__ == "__main__":
    main()
