"""DS: Fenwick Tree (28/50). Fenwick tree (BIT) for prefix sums"""
from __future__ import annotations

import ast

#: Module version.
DS_28_VERSION = "ds-28-fenwick-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-28.fenwick-tree.v1"


class FenwickTree:
    """Binary indexed tree for prefix sums with point updates."""

    def __init__(self, n):
        if n <= 0:
            raise ValueError("n must be positive")
        self._n = n
        self._tree = [0] * (n + 1)

    def add(self, index, delta):
        """Add ``delta`` at 0-based ``index``."""
        if not 0 <= index < self._n:
            raise IndexError("index out of range")
        i = index + 1
        while i <= self._n:
            self._tree[i] += delta
            i += i & -i

    def prefix(self, index):
        """Sum over [0, index)."""
        if not 0 <= index <= self._n:
            raise ValueError("bad index")
        s = 0
        i = index
        while i > 0:
            s += self._tree[i]
            i -= i & -i
        return s

    def range_sum(self, left, right):
        """Sum over [left, right)."""
        return self.prefix(right) - self.prefix(left)

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
    ft = FenwickTree(5)
    for i, v in enumerate([1, 2, 3, 4, 5]):
        ft.add(i, v)
    assert ft.prefix(5) == 15
    assert ft.prefix(3) == 6
    assert ft.range_sum(1, 4) == 9
    ft.add(2, 10)
    assert ft.range_sum(0, 5) == 25
    assert stdlib_only()
    print("ds-28 OK: prefix sums, point updates")


if __name__ == "__main__":
    main()
