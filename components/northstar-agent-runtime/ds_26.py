"""DS: Cartesian Tree (26/50). min Cartesian tree"""
from __future__ import annotations

import ast

#: Module version.
DS_26_VERSION = "ds-26-cartesian-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-26.cartesian-tree.v1"


class CNode:
    """Cartesian tree node."""

    __slots__ = ("val", "idx", "left", "right")

    def __init__(self, val, idx):
        self.val = val
        self.idx = idx
        self.left = None
        self.right = None


def cartesian_tree(arr):
    """Build the min Cartesian tree of ``arr`` in O(n) with a stack."""
    if not arr:
        return None
    nodes = [CNode(v, i) for i, v in enumerate(arr)]
    stack = []
    for node in nodes:
        last = None
        while stack and stack[-1].val > node.val:
            last = stack.pop()
        node.left = last
        if stack:
            stack[-1].right = node
        stack.append(node)
    return stack[0]


def inorder_idx(root):
    """Inorder traversal returning original indices."""
    out = []

    def rec(node):
        if node is None:
            return
        rec(node.left)
        out.append(node.idx)
        rec(node.right)

    rec(root)
    return out


def check_heap(root):
    """Verify the min-heap property."""
    if root is None:
        return True
    for child in (root.left, root.right):
        if child is not None:
            if child.val < root.val:
                return False
            if not check_heap(child):
                return False
    return True

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
    arr = [5, 10, 40, 30, 28]
    root = cartesian_tree(arr)
    assert root.val == 5
    assert inorder_idx(root) == [0, 1, 2, 3, 4]
    assert check_heap(root) is True
    assert cartesian_tree([]) is None
    assert stdlib_only()
    print("ds-26 OK: O(n) stack build, heap property")


if __name__ == "__main__":
    main()
