"""Red-black tree (simplified): self-balancing binary search tree.

simplified: a compact teaching implementation. Insertion follows the
CLRS red-black fix-up: newly inserted nodes are red; violations are
repaired by recoloring (uncle red) and rotations (uncle black: the
triangle case rotates into the line case, the line case rotates and
recolors). The root is always forced black. No deletion, no
key->value payloads, no duplicate handling beyond ignoring them.

Guaranteed invariants after each insert: root is black, no red node
has a red child, every root->leaf path has the same black height.

Complexities: insert O(log n), search O(log n); height <= 2*log2(n+1).
"""

from __future__ import annotations

import ast
import sys
from typing import Any, Optional

ALGO_33_VERSION = "algo-33.v1"

RED = True
BLACK = False


class _Node:
    __slots__ = ("key", "color", "left", "right", "parent")

    def __init__(self, key: Any, color: bool = RED) -> None:
        self.key = key
        self.color = color
        self.left: Optional["_Node"] = None
        self.right: Optional["_Node"] = None
        self.parent: Optional["_Node"] = None


class RBTree:
    """Red-black tree (simplified mock)."""

    def __init__(self) -> None:
        self._root: Optional[_Node] = None
        self._size = 0

    def __len__(self) -> int:
        return self._size

    # -- rotations ------------------------------------------------------
    def _left_rotate(self, x: _Node) -> None:
        y = x.right
        assert y is not None
        x.right = y.left
        if y.left is not None:
            y.left.parent = x
        y.parent = x.parent
        if x.parent is None:
            self._root = y
        elif x is x.parent.left:
            x.parent.left = y
        else:
            x.parent.right = y
        y.left = x
        x.parent = y

    def _right_rotate(self, x: _Node) -> None:
        y = x.left
        assert y is not None
        x.left = y.right
        if y.right is not None:
            y.right.parent = x
        y.parent = x.parent
        if x.parent is None:
            self._root = y
        elif x is x.parent.right:
            x.parent.right = y
        else:
            x.parent.left = y
        y.right = x
        x.parent = y

    # -- insertion ------------------------------------------------------
    def insert(self, key: Any) -> None:
        """Insert key (duplicates ignored) with color fix-up."""
        parent: Optional[_Node] = None
        node = self._root
        while node is not None:
            parent = node
            if key == node.key:
                return  # duplicate: ignore
            node = node.left if key < node.key else node.right
        z = _Node(key, RED)
        z.parent = parent
        if parent is None:
            self._root = z
        elif key < parent.key:
            parent.left = z
        else:
            parent.right = z
        self._size += 1
        self._fix_insert(z)

    def _fix_insert(self, z: _Node) -> None:
        while z.parent is not None and z.parent.color == RED:
            p = z.parent
            g = p.parent
            assert g is not None  # parent red => grandparent exists
            if p is g.left:
                u = g.right  # uncle
                if u is not None and u.color == RED:
                    # Case 1: uncle red -> recolor and move up
                    p.color = BLACK
                    u.color = BLACK
                    g.color = RED
                    z = g
                else:
                    # Case 2: triangle -> rotate into line case
                    if z is p.right:
                        z = p
                        self._left_rotate(z)
                        p = z.parent  # type: ignore[assignment]
                        g = p.parent  # type: ignore[assignment]
                    # Case 3: line -> rotate + recolor
                    p.color = BLACK
                    g.color = RED
                    self._right_rotate(g)
            else:
                u = g.left
                if u is not None and u.color == RED:
                    p.color = BLACK
                    u.color = BLACK
                    g.color = RED
                    z = g
                else:
                    if z is p.left:
                        z = p
                        self._right_rotate(z)
                        p = z.parent  # type: ignore[assignment]
                        g = p.parent  # type: ignore[assignment]
                    p.color = BLACK
                    g.color = RED
                    self._left_rotate(g)
        if self._root is not None:
            self._root.color = BLACK

    def search(self, key: Any) -> bool:
        """Return True if key is present, else False."""
        node = self._root
        while node is not None:
            if key == node.key:
                return True
            node = node.left if key < node.key else node.right
        return False

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

    def check_invariants(self) -> bool:
        """Verify red-black invariants (used by tests)."""
        if self._root is None:
            return True
        if self._root.color != BLACK:
            return False

        def check(node: Optional[_Node]) -> int:
            if node is None:
                return 1  # null leaves count as black
            if node.color == RED:
                if ((node.left is not None and node.left.color == RED)
                        or (node.right is not None and node.right.color == RED)):
                    raise AssertionError("red node with red child")
            left_bh = check(node.left)
            right_bh = check(node.right)
            if left_bh != right_bh:
                raise AssertionError("black-height mismatch")
            return left_bh + (1 if node.color == BLACK else 0)

        check(self._root)
        return True


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
    t = RBTree()
    assert not t.search(1)
    for k in [10, 20, 30, 15, 25, 5, 1, 40, 35]:
        t.insert(k)
        assert t.check_invariants()
    assert t.inorder() == sorted([10, 20, 30, 15, 25, 5, 1, 40, 35])
    assert t.search(25) and not t.search(99)
    t.insert(25)  # duplicate ignored
    assert len(t) == 9
    # Sorted insert still satisfies invariants.
    t2 = RBTree()
    for k in range(50):
        t2.insert(k)
        assert t2.check_invariants()
    assert t2.inorder() == list(range(50))
    assert stdlib_only()
    print("algo_33 OK")


if __name__ == "__main__":
    main()
