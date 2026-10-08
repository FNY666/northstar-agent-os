"""Rebuild-On-Query Point Query: difference array example.

Honest offline-style difference array: each point query rebuilds the prefix in O(n); the rebuild counter makes the cost visible.

What this IS: a real difference array with a visible rebuild counter, fail-closed on bad input
What this IS NOT: pretending queries are O(1)
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_38_VERSION = "rebuild-point-query.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-rebuild-point-query.v1"


class DiffError(Exception):
    """Fail-closed."""


class RebuildDiff:
    """Difference array; query() rebuilds the prefix and counts rebuilds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._d = [0] * (n + 1)
        self.rebuilds = 0

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._d[l] += v
        self._d[r + 1] -= v

    def query(self, i: int) -> int:
        if not (0 <= i < self.n):
            raise DiffError("index out of range")
        self.rebuilds += 1
        cur = 0
        for j in range(i + 1):
            cur += self._d[j]
        return cur

def test_basic():
    r = RebuildDiff(5)
    r.add(0, 4, 2)
    assert r.query(2) == 2
    assert r.rebuilds == 1


def test_after_more_adds():
    r = RebuildDiff(5)
    r.add(0, 4, 2)
    r.add(1, 3, 3)
    assert r.query(3) == 5
    assert r.query(0) == 2


def test_no_adds():
    r = RebuildDiff(3)
    assert r.query(1) == 0


def test_bad():
    r = RebuildDiff(3)
    try:
        r.query(3)
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
    test_after_more_adds()
    test_no_adds()
    test_bad()
    assert stdlib_only()
    print("diff-38 OK: rebuild-point-query")


if __name__ == "__main__":
    main()
