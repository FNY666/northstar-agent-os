"""Weight-balanced tree (mock): BB[alpha] rotations. Stdlib only."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

ALPHA, BETA = 0.29, 0.71

@dataclass
class WNode:
    key: int
    left: Optional["WNode"] = None
    right: Optional["WNode"] = None
    size: int = 1

def _sz(n) -> int: return n.size if n else 0
def _upd(n):
    n.size = 1 + _sz(n.left) + _sz(n.right)
    return n

def _rot_r(y):
    x = y.left; y.left = x.right; x.right = y
    _upd(y); _upd(x); return x
def _rot_l(x):
    y = x.right; x.right = y.left; y.left = x
    _upd(x); _upd(y); return y

def _balance(n):
    _upd(n)
    ls, rs = _sz(n.left), _sz(n.right)
    if ls > (ALPHA + BETA) / 2 * (ls + rs + 1) and ls > 0:
        if _sz(n.left.right) > BETA * ls: n.left = _rot_l(n.left)
        return _rot_r(n)
    if rs > (ALPHA + BETA) / 2 * (ls + rs + 1) and rs > 0:
        if _sz(n.right.left) > BETA * rs: n.right = _rot_r(n.right)
        return _rot_l(n)
    return n

def wb_insert(n, key):
    if n is None: return WNode(key)
    if key < n.key: n.left = wb_insert(n.left, key)
    elif key > n.key: n.right = wb_insert(n.right, key)
    else: return n
    return _balance(n)

def inorder(n, out: List[int]):
    if n is not None: inorder(n.left, out); out.append(n.key); inorder(n.right, out)

def main() -> None:
    r = None
    for k in range(20): r = wb_insert(r, k)
    out: List[int] = []; inorder(r, out)
    assert out == list(range(20))
    assert r.size == 20
    print("tree_47 Weight-balanced (mock) OK")

if __name__ == "__main__":
    main()
