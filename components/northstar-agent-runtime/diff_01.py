"""Range Add Point Query: difference array example.

The canonical 1D difference array: add v to every index in [l, r], then answer point queries. Offline batch updates become O(1) each.

What this IS: a real O(n+q) range-add/point-query via a difference array, fail-closed on bad bounds
What this IS NOT: a Fenwick tree or segment tree; the host picks the data structure
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_01_VERSION = "range-add-point-query.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-add-point-query.v1"


class DiffError(Exception):
    """Fail-closed."""


class RangeAddPointQuery:
    """1D difference array: range add, point query. Fail-closed on bad bounds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._diff = [0] * (n + 1)

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._diff[l] += v
        self._diff[r + 1] -= v

    def build(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            cur += self._diff[i]
            out.append(cur)
        return out

    def query(self, i: int) -> int:
        if not (0 <= i < self.n):
            raise DiffError("index out of range")
        return self.build()[i]

def test_basic():
    q = RangeAddPointQuery(5)
    q.add(1, 3, 2)
    assert q.build() == [0, 2, 2, 2, 0]


def test_overlap():
    q = RangeAddPointQuery(5)
    q.add(0, 4, 1)
    q.add(2, 4, 3)
    assert q.build() == [1, 1, 4, 4, 4]


def test_point_query():
    q = RangeAddPointQuery(5)
    q.add(0, 4, 1)
    q.add(2, 4, 3)
    assert q.query(2) == 4
    assert q.query(0) == 1


def test_bad_bounds():
    q = RangeAddPointQuery(5)
    for bad in (lambda: q.add(3, 2, 1), lambda: q.add(0, 5, 1),
                lambda: q.add(-1, 2, 1), lambda: q.query(5)):
        try:
            bad()
        except DiffError:
            continue
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
    test_overlap()
    test_point_query()
    test_bad_bounds()
    assert stdlib_only()
    print("diff-01 OK: range-add-point-query")


if __name__ == "__main__":
    main()
