"""DS: Binary Search Tree (11/50). binary search tree"""
from __future__ import annotations

import ast

#: Module version.
DS_11_VERSION = "ds-11-bst.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-11.bst.v1"


class _BSTNode:
    __slots__ = ("key", "left", "right")

    def __init__(self, key):
        self.key = key
        self.left = None
        self.right = None


class BST:
    """Binary search tree with insert/search/delete."""

    def __init__(self):
        self._root = None
        self._size = 0

    def insert(self, key):
        if self._root is None:
            self._root = _BSTNode(key)
            self._size = 1
            return
        node = self._root
        while True:
            if key == node.key:
                return
            if key < node.key:
                if node.left is None:
                    node.left = _BSTNode(key)
                    self._size += 1
                    return
                node = node.left
            else:
                if node.right is None:
                    node.right = _BSTNode(key)
                    self._size += 1
                    return
                node = node.right

    def search(self, key):
        node = self._root
        while node is not None:
            if key == node.key:
                return True
            node = node.left if key < node.key else node.right
        return False

    def delete(self, key):
        self._root, removed = self._delete(self._root, key)
        if removed:
            self._size -= 1
        return removed

    def _delete(self, node, key):
        if node is None:
            return None, False
        if key < node.key:
            node.left, removed = self._delete(node.left, key)
            return node, removed
        if key > node.key:
            node.right, removed = self._delete(node.right, key)
            return node, removed
        if node.left is None:
            return node.right, True
        if node.right is None:
            return node.left, True
        succ = node.right
        while succ.left is not None:
            succ = succ.left
        node.key = succ.key
        node.right, _ = self._delete(node.right, succ.key)
        return node, True

    def inorder(self):
        out = []

        def rec(node):
            if node is None:
                return
            rec(node.left)
            out.append(node.key)
            rec(node.right)

        rec(self._root)
        return out

    def __len__(self):
        return self._size

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    t = BST()
    for k in (5, 3, 7, 2, 4, 6, 8):
        t.insert(k)
    assert t.inorder() == [2, 3, 4, 5, 6, 7, 8]
    assert t.search(4) is True
    assert t.search(9) is False
    assert t.delete(3) is True
    assert t.inorder() == [2, 4, 5, 6, 7, 8]
    assert t.delete(5) is True
    assert t.inorder() == [2, 4, 6, 7, 8]
    assert t.delete(99) is False
    assert stdlib_only()
    print("ds-11 OK: insert/search/delete, sorted inorder")


if __name__ == "__main__":
    main()
