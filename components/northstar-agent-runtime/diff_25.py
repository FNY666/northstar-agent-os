"""Range Flip Point Query: difference array example.

Binary array with range flips; the difference array works mod 2, so flips compose with XOR.

What this IS: a real mod-2 difference structure for range flips, fail-closed on bad bounds
What this IS NOT: flipping each element per operation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_25_VERSION = "range-flip-query.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-range-flip-query.v1"


class DiffError(Exception):
    """Fail-closed."""


class FlipDiff:
    """Range flip on a binary array, point query. Fail-closed on bad bounds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._diff = [0] * (n + 1)

    def flip(self, l: int, r: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._diff[l] ^= 1
        self._diff[r + 1] ^= 1

    def query(self, i: int) -> int:
        if not (0 <= i < self.n):
            raise DiffError("index out of range")
        cur = 0
        for j in range(i + 1):
            cur ^= self._diff[j]
        return cur

    def to_list(self) -> list:
        return [self.query(i) for i in range(self.n)]

def test_basic():
    f = FlipDiff(5)
    f.flip(1, 3)
    assert f.to_list() == [0, 1, 1, 1, 0]


def test_overlap():
    f = FlipDiff(5)
    f.flip(1, 3)
    f.flip(2, 4)
    assert f.to_list() == [0, 1, 0, 0, 1]


def test_double_flip():
    f = FlipDiff(3)
    f.flip(0, 2)
    f.flip(0, 2)
    assert f.to_list() == [0, 0, 0]


def test_bad():
    f = FlipDiff(3)
    try:
        f.flip(2, 5)
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
    test_overlap()
    test_double_flip()
    test_bad()
    assert stdlib_only()
    print("diff-25 OK: range-flip-query")


if __name__ == "__main__":
    main()
