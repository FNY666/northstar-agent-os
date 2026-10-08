"""Treap (mock): randomized BST by (key, priority), split/merge. Stdlib only."""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

@dataclass
class Node:
    key: int
    prio: float
    left: Optional["Node"] = None
    right: Optional["Node"] = None

def _upd(n): return n

def split(root, key) -> Tuple[Optional[Node], Optional[Node]]:
    if root is None: return None, None
    if key <= root.key:
        l, r = split(root.left, key)
        root.left = r
        return l, root
    l, r = split(root.right, key)
    root.right = l
    return root, r

def merge(a, b):
    if a is None: return b
    if b is None: return a
    if a.prio > b.prio:
        a.right = merge(a.right, b)
        return a
    b.left = merge(a, b.left)
    return b

def treap_insert(root, key, rng) -> Optional[Node]:
    l, r = split(root, key)
    return merge(merge(l, Node(key, rng.random())), r)

def treap_search(root, key) -> bool:
    while root is not None:
        if key == root.key: return True
        root = root.left if key < root.key else root.right
    return False

def inorder(root, out: List[int]) -> None:
    if root is not None: inorder(root.left, out); out.append(root.key); inorder(root.right, out)

def main() -> None:
    rng = random.Random(42)
    root = None
    for k in [5, 2, 8, 1, 9, 3]: root = treap_insert(root, k, rng)
    out: List[int] = []; inorder(root, out)
    assert out == [1, 2, 3, 5, 8, 9]
    assert treap_search(root, 8) and not treap_search(root, 7)
    l, r = split(root, 5)
    lo: List[int] = []; hi: List[int] = []
    inorder(l, lo); inorder(r, hi)
    assert lo == [1, 2, 3] and hi == [5, 8, 9]
    print("tree_13 Treap (mock) OK")

if __name__ == "__main__":
    main()
