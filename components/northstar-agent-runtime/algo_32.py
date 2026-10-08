"""AVL tree (simplified): self-balancing binary search tree.

simplified: a compact teaching implementation. Insert performs the
standard BST insertion, then walks back up updating heights and
applying single/double rotations (left/right/left-right/right-left)
whenever |balance| > 1. No deletion, no key->value payloads, no
thread-safety, no bulk loading.

Complexities: insert O(log n), search O(log n); height is guaranteed
<= ~1.44*log2(n+2). Tests assert height <= 2*log2(n+1) for n >= 1.
"""

from __future__ import annotations

import ast
import sys
from typing import Any, Optional

ALGO_32_VERSION = "algo-32.v1"


class _Node:
    __slots__ = ("key", "left", "right", "height")

    def __init__(self, key: Any) -> None:
        self.key = key
        self.left: Optional["_Node"] = None
        self.right: Optional["_Node"] = None
        self.height = 1


def _h(node: Optional[_Node]) -> int:
    return node.height if node is not None else 0


def _balance(node: _Node) -> int:
    return _h(node.left) - _h(node.right)


def _fix_height(node: _Node) -> None:
    node.height = 1 + max(_h(node.left), _h(node.right))


def _rotate_right(y: _Node) -> _Node:
    x = y.left  # type: ignore[union-attr]
    t2 = x.right
    x.right = y
    y.left = t2
    _fix_height(y)
    _fix_height(x)
    return x


def _rotate_left(x: _Node) -> _Node:
    y = x.right  # type: ignore[union-attr]
    t2 = y.left
    y.left = x
    x.right = t2
    _fix_height(x)
    _fix_height(y)
    return y


class AVLTree:
    """Self-balancing BST (simplified mock)."""

    def __init__(self) -> None:
        self._root: Optional[_Node] = None
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def insert(self, key: Any) -> None:
        """Insert key (duplicates ignored) and rebalance on the way up."""
        self._root = self._insert(self._root, key)

    def _insert(self, node: Optional[_Node], key: Any) -> _Node:
        if node is None:
            self._size += 1
            return _Node(key)
        if key < node.key:
            node.left = self._insert(node.left, key)
        elif key > node.key:
            node.right = self._insert(node.right, key)
        else:
            return node  # duplicate: ignore
        _fix_height(node)
        bal = _balance(node)
        # Left-Left
        if bal > 1 and key < node.left.key:  # type: ignore[union-attr]
            return _rotate_right(node)
        # Right-Right
        if bal < -1 and key > node.right.key:  # type: ignore[union-attr]
            return _rotate_left(node)
        # Left-Right
        if bal > 1 and key > node.left.key:  # type: ignore[union-attr]
            node.left = _rotate_left(node.left)
            return _rotate_right(node)
        # Right-Left
        if bal < -1 and key < node.right.key:  # type: ignore[union-attr]
            node.right = _rotate_right(node.right)
            return _rotate_left(node)
        return node

    def search(self, key: Any) -> bool:
        """Return True if key is present, else False."""
        node = self._root
        while node is not None:
            if key == node.key:
                return True
            node = node.left if key < node.key else node.right
        return False

    def height(self) -> int:
        """Return the height of the tree (0 for empty)."""
        return _h(self._root)

    def inorder(self) -> list:
        """Return keys in sorted order (used by tests)."""
        out: list = []

        def visit(node: Optional[_Node]) -> None:
            if node is None:
                return
            visit(node.left)
            out.append(node.key)
            visit(node.right)

        visit(self._root)
        return out


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    import math

    t = AVLTree()
    assert t.height() == 0
    assert not t.search(1)
    # Worst case for plain BST: sorted insert; AVL must stay balanced.
    for k in range(1, 101):
        t.insert(k)
    n = len(t)
    assert n == 100
    assert t.height() <= 2 * math.log2(n + 1)
    assert t.inorder() == list(range(1, 101))
    assert t.search(50) and t.search(1) and t.search(100)
    assert not t.search(0)
    t.insert(50)  # duplicate ignored
    assert len(t) == 100
    assert stdlib_only()
    print("algo_32 OK")


if __name__ == "__main__":
    main()
