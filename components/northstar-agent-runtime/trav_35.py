"""DFS with an explicit state machine (enter/exit states). Stdlib only."""
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


ENTER, EXIT = 0, 1
def dfs_states(root: Optional[Node]) -> List:
    if root is None: return []
    out, st = [], [(root, ENTER)]
    while st:
        n, state = st.pop()
        if state == ENTER:
            out.append(("enter", n.val))
            st.append((n, EXIT))
            if n.right: st.append((n.right, ENTER))
            if n.left: st.append((n.left, ENTER))
        else:
            out.append(("exit", n.val))
    return out

def main() -> None:
    e = dfs_states(sample()); assert e[0] == ('enter', 1) and e[-1] == ('exit', 1)
    assert dfs_states(None) == []
    assert dfs_states(Node(1)) == [('enter', 1), ('exit', 1)]
    print("trav_35 OK")


if __name__ == "__main__":
    main()
