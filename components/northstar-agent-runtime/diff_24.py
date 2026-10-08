"""Range XOR Update Point Query: difference array example.

Difference array over XOR: range-xor updates cancel out with the XOR group operation, giving O(1) updates and O(n) point queries.

What this IS: a real XOR-difference structure, fail-closed on bad bounds
What this IS NOT: a bitwise segment tree
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_24_VERSION = "range-xor-update.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-xor-update.v1"


class DiffError(Exception):
    """Fail-closed."""


class XorDiff:
    """Range xor update, point query. Fail-closed on bad bounds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._diff = [0] * (n + 1)

    def xor_range(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._diff[l] ^= v
        self._diff[r + 1] ^= v

    def query(self, i: int) -> int:
        if not (0 <= i < self.n):
            raise DiffError("index out of range")
        cur = 0
        for j in range(i + 1):
            cur ^= self._diff[j]
        return cur

def test_basic():
    x = XorDiff(4)
    x.xor_range(0, 2, 5)
    x.xor_range(1, 3, 5)
    assert [x.query(i) for i in range(4)] == [5, 0, 0, 5]


def test_double_cancel():
    x = XorDiff(3)
    x.xor_range(0, 2, 7)
    x.xor_range(0, 2, 7)
    assert [x.query(i) for i in range(3)] == [0, 0, 0]


def test_single():
    x = XorDiff(2)
    x.xor_range(1, 1, 9)
    assert x.query(0) == 0
    assert x.query(1) == 9


def test_bad():
    x = XorDiff(2)
    try:
        x.xor_range(0, 2, 1)
    except DiffError:
        return
    raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
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
    test_basic()
    test_double_cancel()
    test_single()
    test_bad()
    assert stdlib_only()
    print("diff-24 OK: range-xor-update")


if __name__ == "__main__":
    main()
