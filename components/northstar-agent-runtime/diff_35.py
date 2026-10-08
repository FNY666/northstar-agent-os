"""Sparse Dict Difference Array: difference array example.

Dict-based difference array for huge coordinate ranges: only touched coordinates are stored; queries sweep the sorted keys.

What this IS: a real sparse difference map, fail-closed on l > r
What this IS NOT: allocating an array over the full coordinate range
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_35_VERSION = "sparse-diff.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-sparse-diff.v1"


class DiffError(Exception):
    """Fail-closed."""


class SparseDiff:
    """Dict-based difference array for huge ranges."""

    def __init__(self):
        self._d = {}

    def add(self, l: int, r: int, v: int) -> None:
        if l > r:
            raise DiffError("need l <= r")
        self._d[l] = self._d.get(l, 0) + v
        self._d[r + 1] = self._d.get(r + 1, 0) - v

    def query(self, x: int) -> int:
        cur = 0
        for k in sorted(self._d):
            if k > x:
                break
            cur += self._d[k]
        return cur

    def keys(self) -> list:
        return sorted(self._d)

def test_huge_range():
    s = SparseDiff()
    s.add(10 ** 12, 10 ** 12 + 5, 7)
    assert s.query(10 ** 12 + 3) == 7
    assert s.query(0) == 0
    assert s.query(10 ** 12 + 6) == 0


def test_overlap():
    s = SparseDiff()
    s.add(5, 10, 3)
    s.add(8, 12, 4)
    assert s.query(9) == 7
    assert s.query(11) == 4


def test_keys():
    s = SparseDiff()
    s.add(5, 10, 3)
    assert s.keys() == [5, 11]


def test_bad():
    s = SparseDiff()
    try:
        s.add(10, 5, 1)
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
    test_huge_range()
    test_overlap()
    test_keys()
    test_bad()
    assert stdlib_only()
    print("diff-35 OK: sparse-diff")


if __name__ == "__main__":
    main()
