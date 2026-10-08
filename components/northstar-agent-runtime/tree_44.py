"""Threaded binary tree (mock): inorder threading for stackless traversal. Stdlib only."""
from __future__ import annotations
from typing import List, Optional

class TNode:
    def __init__(self, key: int) -> None:
        self.key = key
        self.left: Optional["TNode"] = None
        self.right: Optional["TNode"] = None
        self.left_thread = False
        self.right_thread = False

def insert(root, key) -> TNode:
    if root is None: return TNode(key)
    if key < root.key:
        if root.left is None or root.left_thread:
            n = TNode(key)
            n.left, n.left_thread = root.left, True
            n.right, n.right_thread = root, True
            root.left, root.left_thread = n, False
        else: insert(root.left, key)
    elif key > root.key:
        if root.right is None or root.right_thread:
            n = TNode(key)
            n.right, n.right_thread = root.right, True
            n.left, n.left_thread = root, True
            root.right, root.right_thread = n, False
        else: insert(root.right, key)
    return root

def leftmost(n: TNode) -> TNode:
    while n.left is not None and not n.left_thread: n = n.left
    return n

def inorder_threaded(root) -> List[int]:
    out: List[int] = []
    if root is None: return out
    cur = leftmost(root)
    while cur is not None:
        out.append(cur.key)
        if cur.right_thread: cur = cur.right
        else:
            cur = cur.right
            if cur is not None: cur = leftmost(cur)
    return out

def main() -> None:
    root = None
    for k in [5, 3, 7, 2, 4]: root = insert(root, k)
    assert inorder_threaded(root) == [2, 3, 4, 5, 7]
    assert inorder_threaded(None) == []
    print("tree_44 Threaded binary tree (mock) OK")

if __name__ == "__main__":
    main()
