"""AVL tree: self-balancing BST with rotations. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Node:
    key: int
    left: Optional["Node"] = None
    right: Optional["Node"] = None
    height: int = 1

def _h(n) -> int: return n.height if n else 0
def _upd(n) -> None: n.height = 1 + max(_h(n.left), _h(n.right))
def _bal(n) -> int: return _h(n.left) - _h(n.right)

def _rot_right(y):
    x = y.left; t = x.right
    x.right = y; y.left = t
    _upd(y); _upd(x); return x

def _rot_left(x):
    y = x.right; t = y.left
    y.left = x; x.right = t
    _upd(x); _upd(y); return y

def _rebalance(n):
    _upd(n)
    b = _bal(n)
    if b > 1:
        if _bal(n.left) < 0: n.left = _rot_left(n.left)
        return _rot_right(n)
    if b < -1:
        if _bal(n.right) > 0: n.right = _rot_right(n.right)
        return _rot_left(n)
    return n

def avl_insert(root, key):
    if root is None: return Node(key)
    if key < root.key: root.left = avl_insert(root.left, key)
    elif key > root.key: root.right = avl_insert(root.right, key)
    else: return root
    return _rebalance(root)

def inorder(root, out):
    if root is not None: inorder(root.left, out); out.append(root.key); inorder(root.right, out)

def is_balanced(n) -> bool:
    if n is None: return True
    return abs(_bal(n)) <= 1 and is_balanced(n.left) and is_balanced(n.right)

def main() -> None:
    root = None
    for k in range(1, 16): root = avl_insert(root, k)
    out: List[int] = []; inorder(root, out)
    assert out == list(range(1, 16))
    assert is_balanced(root)
    assert root.height <= 5
    print("tree_02 AVL OK")

if __name__ == "__main__":
    main()
