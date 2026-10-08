"""Tree sort: BST insert plus inorder traversal.

Inserts every element into a binary search tree, then reads the tree back with an inorder traversal.

What this IS: quicksort's tree-shaped sibling; O(n log n) average.

What this IS NOT:
* Degrades to O(n^2) on sorted input without balancing.
* No self-balancing here -- see the disclaimer, not a red-black tree.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_37_VERSION = "sort-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-37.v1"


class _Node:
    __slots__ = ("v", "left", "right")

    def __init__(self, v: int) -> None:
        self.v = v
        self.left = None
        self.right = None


def _insert(node, x: int):
    if node is None:
        return _Node(x)
    if x < node.v:
        node.left = _insert(node.left, x)
    else:
        node.right = _insert(node.right, x)
    return node


def _inorder(node, out: List[int]) -> None:
    if node is None:
        return
    _inorder(node.left, out)
    out.append(node.v)
    _inorder(node.right, out)


def sort(data: List[int]) -> List[int]:
    # Tree sort: insert every element into a binary search tree, then
    # read it back with an inorder traversal.
    root = None
    for x in data:
        root = _insert(root, x)
    out: List[int] = []
    _inorder(root, out)
    return out

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert sort([]) == []
    assert sort([1]) == [1]
    assert sort([3, 1, 2]) == [1, 2, 3]
    assert sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert sort([-3, 0, -1, 2]) == [-3, -1, 0, 2]
    assert sort([2, 2, 1, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("tree OK")


if __name__ == "__main__":
    main()
