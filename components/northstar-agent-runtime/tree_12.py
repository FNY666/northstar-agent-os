"""Cartesian tree: min-heap ordered by array index (inorder = array). Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Node:
    val: int
    idx: int
    left: Optional["Node"] = None
    right: Optional["Node"] = None

def build_cartesian(arr: List[int]) -> Optional[Node]:
    stack: List[Node] = []
    root: Optional[Node] = None
    for i, v in enumerate(arr):
        node = Node(v, i)
        last = None
        while stack and stack[-1].val > v:
            last = stack.pop()
        node.left = last
        if stack:
            stack[-1].right = node
        else:
            root = node
        stack.append(node)
    return root

def inorder_idx(n) -> List[int]:
    out: List[int] = []
    def rec(x):
        if x is not None: rec(x.left); out.append(x.idx); rec(x.right)
    rec(n); return out

def is_min_heap(n) -> bool:
    if n is None: return True
    for c in (n.left, n.right):
        if c is not None and c.val < n.val: return False
    return is_min_heap(n.left) and is_min_heap(n.right)

def main() -> None:
    arr = [3, 1, 4, 2, 5]
    root = build_cartesian(arr)
    assert root is not None and root.val == 1
    assert inorder_idx(root) == [0, 1, 2, 3, 4]
    assert is_min_heap(root)
    print("tree_12 Cartesian tree OK")

if __name__ == "__main__":
    main()
