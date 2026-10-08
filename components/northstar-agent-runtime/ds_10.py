"""DS: Binary Tree (10/50). binary tree with traversals"""
from __future__ import annotations

import ast

#: Module version.
DS_10_VERSION = "ds-10-binary-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-10.binary-tree.v1"


class TreeNode:
    """Binary tree node."""

    def __init__(self, val, left=None, right=None):
        self.val = val
        self.left = left
        self.right = right


def inorder(root):
    out = []

    def rec(node):
        if node is None:
            return
        rec(node.left)
        out.append(node.val)
        rec(node.right)

    rec(root)
    return out


def preorder(root):
    out = []

    def rec(node):
        if node is None:
            return
        out.append(node.val)
        rec(node.left)
        rec(node.right)

    rec(root)
    return out


def postorder(root):
    out = []

    def rec(node):
        if node is None:
            return
        rec(node.left)
        rec(node.right)
        out.append(node.val)

    rec(root)
    return out


def height(root):
    if root is None:
        return 0
    return 1 + max(height(root.left), height(root.right))

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
    root = TreeNode(1, TreeNode(2, TreeNode(4), TreeNode(5)), TreeNode(3))
    assert inorder(root) == [4, 2, 5, 1, 3]
    assert preorder(root) == [1, 2, 4, 5, 3]
    assert postorder(root) == [4, 5, 2, 3, 1]
    assert height(root) == 3
    assert height(None) == 0
    assert stdlib_only()
    print("ds-10 OK: inorder/preorder/postorder/height")


if __name__ == "__main__":
    main()
