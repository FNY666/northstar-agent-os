"""Euler tour recording entry and exit times. Stdlib only."""
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


def euler_tour(root: Optional[Node]) -> List:
    out: List = []
    clock = [0]
    def walk(n):
        if n is None: return
        out.append(("in", n.val, clock[0])); clock[0] += 1
        walk(n.left); walk(n.right)
        out.append(("out", n.val, clock[0])); clock[0] += 1
    walk(root); return out

def main() -> None:
    t = euler_tour(sample()); assert len(t) == 12
    assert euler_tour(None) == []
    t = euler_tour(sample()); assert t[0] == ('in', 1, 0) and t[-1] == ('out', 1, 11)
    print("trav_29 OK")


if __name__ == "__main__":
    main()
