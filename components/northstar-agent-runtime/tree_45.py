"""AA tree (mock): skew/split balanced BST. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ANode:
    key: int
    level: int = 1
    left: Optional["ANode"] = None
    right: Optional["ANode"] = None

def skew(n):
    if n is None or n.left is None: return n
    if n.left.level == n.level:
        l = n.left; n.left = l.right; l.right = n
        return l
    return n

def split(n):
    if n is None or n.right is None or n.right.right is None: return n
    if n.level == n.right.right.level:
        r = n.right; n.right = r.left; r.left = n; r.level += 1
        return r
    return n

def aa_insert(n, key):
    if n is None: return ANode(key)
    if key < n.key: n.left = aa_insert(n.left, key)
    elif key > n.key: n.right = aa_insert(n.right, key)
    else: return n
    n = skew(n); n = split(n)
    return n

def inorder(n, out: List[int]):
    if n is not None: inorder(n.left, out); out.append(n.key); inorder(n.right, out)

def check_levels(n) -> bool:
    # AA invariant: left.level < n.level; right.level in {n.level-1, n.level}
    if n is None: return True
    if n.left and n.left.level >= n.level: return False
    if n.right and n.right.level not in (n.level - 1, n.level): return False
    return check_levels(n.left) and check_levels(n.right)

def main() -> None:
    r = None
    for k in range(1, 11): r = aa_insert(r, k)
    out: List[int] = []; inorder(r, out)
    assert out == list(range(1, 11))
    assert check_levels(r)
    print("tree_45 AA tree (mock) OK")

if __name__ == "__main__":
    main()
