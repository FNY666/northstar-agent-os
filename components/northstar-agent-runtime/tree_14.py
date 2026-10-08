"""Splay tree (mock): rotations bring accessed node to root. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Node:
    key: int
    left: Optional["Node"] = None
    right: Optional["Node"] = None

def _rot_right(y):
    x = y.left; y.left = x.right; x.right = y; return x
def _rot_left(x):
    y = x.right; x.right = y.left; y.left = x; return y

def splay(root, key):
    if root is None or root.key == key: return root
    if key < root.key:
        if root.left is None: return root
        if key < root.left.key:
            root.left.left = splay(root.left.left, key)
            root = _rot_right(root)
        elif key > root.left.key:
            root.left.right = splay(root.left.right, key)
            if root.left.right is not None: root.left = _rot_left(root.left)
        return _rot_right(root) if root.left is not None else root
    if root.right is None: return root
    if key > root.right.key:
        root.right.right = splay(root.right.right, key)
        root = _rot_left(root)
    elif key < root.right.key:
        root.right.left = splay(root.right.left, key)
        if root.right.left is not None: root.right = _rot_right(root.right)
    return _rot_left(root) if root.right is not None else root

def splay_insert(root, key):
    if root is None: return Node(key)
    root = splay(root, key)
    if root.key == key: return root
    n = Node(key)
    if key < root.key: n.right = root; n.left = root.left; root.left = None
    else: n.left = root; n.right = root.right; root.right = None
    return n

def splay_search(root, key):
    root = splay(root, key)
    return root, (root is not None and root.key == key)

def main() -> None:
    root = None
    for k in [5, 3, 7, 2]: root = splay_insert(root, k)
    root, found = splay_search(root, 2)
    assert found and root is not None and root.key == 2
    root, found = splay_search(root, 99)
    assert not found
    print("tree_14 Splay (mock) OK")

if __name__ == "__main__":
    main()
