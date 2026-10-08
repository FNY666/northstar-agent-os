"""Scapegoat tree (mock): rebuild on alpha-imbalance. Stdlib only."""
from __future__ import annotations
from typing import List, Optional

ALPHA = 0.75

class SNode:
    def __init__(self, key: int) -> None:
        self.key = key
        self.left: Optional["SNode"] = None
        self.right: Optional["SNode"] = None

def _size(n) -> int: return 0 if n is None else 1 + _size(n.left) + _size(n.right)
def _height(n) -> int: return 0 if n is None else 1 + max(_height(n.left), _height(n.right))

def _flatten(n, out: List[int]):
    if n is not None: _flatten(n.left, out); out.append(n.key); _flatten(n.right, out)

def _build_balanced(keys: List[int]) -> Optional[SNode]:
    if not keys: return None
    m = len(keys) // 2
    n = SNode(keys[m])
    n.left = _build_balanced(keys[:m]); n.right = _build_balanced(keys[m + 1:])
    return n

class ScapegoatMock:
    def __init__(self) -> None:
        self.root: Optional[SNode] = None
        self.n = 0
    def insert(self, key: int) -> None:
        self.root = self._ins(self.root, key)
    def _ins(self, n, key):
        if n is None:
            self.n += 1
            return SNode(key)
        if key < n.key: n.left = self._ins(n.left, key)
        elif key > n.key: n.right = self._ins(n.right, key)
        else: return n
        if _height(n) > int(1 + 3.0 * (_size(n).bit_length())) and _size(n) > 3:
            keys: List[int] = []; _flatten(n, keys)
            return _build_balanced(sorted(keys))
        return n
    def inorder(self) -> List[int]:
        out: List[int] = []; _flatten(self.root, out); return out

def main() -> None:
    s = ScapegoatMock()
    for k in range(15): s.insert(k)
    assert s.inorder() == list(range(15))
    assert s.n == 15
    print("tree_46 Scapegoat (mock) OK")

if __name__ == "__main__":
    main()
