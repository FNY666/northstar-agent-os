"""Interval tree: stabbing/overlap queries over intervals. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Tuple

Interval = Tuple[int, int]

@dataclass
class INode:
    iv: Interval
    max_end: int
    left: Optional["INode"] = None
    right: Optional["INode"] = None

def insert(root, iv: Interval) -> INode:
    if root is None: return INode(iv, iv[1])
    if iv[0] < root.iv[0]: root.left = insert(root.left, iv)
    else: root.right = insert(root.right, iv)
    root.max_end = max(root.max_end, iv[1])
    return root

def _overlap(a: Interval, b: Interval) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]

def query(root, q: Interval, out: List[Interval]) -> None:
    if root is None: return
    if _overlap(root.iv, q): out.append(root.iv)
    if root.left is not None and root.left.max_end >= q[0]:
        query(root.left, q, out)
    if root.right is not None and root.iv[0] <= q[1]:
        query(root.right, q, out)

def main() -> None:
    root = None
    for iv in [(1, 3), (5, 8), (2, 6), (10, 12)]: root = insert(root, iv)
    out: List[Interval] = []; query(root, (2, 5), out)
    assert sorted(out) == [(1, 3), (2, 6), (5, 8)]
    out = []; query(root, (9, 9), out)
    assert out == []
    out = []; query(root, (10, 11), out)
    assert out == [(10, 12)]
    print("tree_21 Interval tree OK")

if __name__ == "__main__":
    main()
