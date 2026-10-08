"""Binary search tree (BST) with key->value mapping.

A BST stores keys with the invariant: every key in the left subtree is
< the node's key and every key in the right subtree is > the node's key.
Complexities (average case): insert O(log n), search O(log n),
inorder traversal O(n). Worst case (degenerate, e.g. sorted inserts)
is O(n) per op -- see algo_32.py (AVL) for a balanced variant.

Duplicate inserts are ignored: the first value stored for a key wins.
"""

from __future__ import annotations

import ast
import sys
from typing import Any, Dict, List, Optional

ALGO_31_VERSION = "algo-31.v1"


class _Node:
    __slots__ = ("key", "value", "left", "right")

    def __init__(self, key: Any, value: Any) -> None:
        self.key = key
        self.value = value
        self.left: Optional["_Node"] = None
        self.right: Optional["_Node"] = None


class BST:
    """Binary search tree mapping keys to values."""

    def __init__(self) -> None:
        self._root: Optional[_Node] = None
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def insert(self, key: Any, value: Any = None) -> None:
        """Insert key->value. Duplicate keys keep the first value."""
        if self._root is None:
            self._root = _Node(key, value)
            self._size += 1
            return
        node = self._root
        while True:
            if key == node.key:
                return  # duplicate: ignore, keep first
            if key < node.key:
                if node.left is None:
                    node.left = _Node(key, value)
                    self._size += 1
                    return
                node = node.left
            else:
                if node.right is None:
                    node.right = _Node(key, value)
                    self._size += 1
                    return
                node = node.right

    def search(self, key: Any) -> Optional[Any]:
        """Return the value stored for key, or None if absent."""
        node = self._root
        while node is not None:
            if key == node.key:
                return node.value
            node = node.left if key < node.key else node.right
        return None

    def inorder(self) -> List[Any]:
        """Return keys in ascending sorted order."""
        out: List[Any] = []
        stack: List[_Node] = []
        node = self._root
        while stack or node is not None:
            while node is not None:
                stack.append(node)
                node = node.left
            node = stack.pop()
            out.append(node.key)
            node = node.right
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
    b = BST()
    assert b.search(1) is None
    assert b.inorder() == []
    for k, v in [(5, "e"), (3, "c"), (7, "g"), (1, "a"), (4, "d")]:
        b.insert(k, v)
    b.insert(5, "E")  # duplicate: ignored
    assert b.search(5) == "e"
    assert b.search(4) == "d"
    assert b.search(99) is None
    assert b.inorder() == [1, 3, 4, 5, 7]
    assert len(b) == 5
    assert stdlib_only()
    print("algo_31 OK")


if __name__ == "__main__":
    main()
