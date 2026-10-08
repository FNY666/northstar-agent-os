"""Circular Range Add: difference array example.

Range adds on a circular array: a range of `length` cells starting at l may wrap around; split into at most two linear difference updates.

What this IS: a real wrap-aware circular difference array, fail-closed on bad input
What this IS NOT: rotating the array per update
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_36_VERSION = "circular-range-add.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-circular-range-add.v1"


class DiffError(Exception):
    """Fail-closed."""


class CircularDiff:
    """Circular array range adds via a linear difference array."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._d = [0] * (n + 1)

    def add(self, l: int, length: int, v: int) -> None:
        """Add v to `length` cells starting at l (wrapping)."""
        if not (0 <= l < self.n) or length <= 0:
            raise DiffError("bad l or length")
        if length >= self.n:
            self._d[0] += v
            self._d[self.n] -= v
            return
        end = l + length - 1
        if end < self.n:
            self._d[l] += v
            self._d[end + 1] -= v
        else:
            self._d[l] += v
            self._d[self.n] -= v
            self._d[0] += v
            self._d[end - self.n + 1] -= v

    def build(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            cur += self._d[i]
            out.append(cur)
        return out

def test_wrap():
    c = CircularDiff(5)
    c.add(3, 4, 2)
    assert c.build() == [2, 2, 0, 2, 2]


def test_no_wrap():
    c = CircularDiff(5)
    c.add(1, 2, 3)
    assert c.build() == [0, 3, 3, 0, 0]


def test_full():
    c = CircularDiff(4)
    c.add(2, 4, 1)
    assert c.build() == [1, 1, 1, 1]


def test_bad():
    c = CircularDiff(4)
    try:
        c.add(4, 2, 1)
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
    test_wrap()
    test_no_wrap()
    test_full()
    test_bad()
    assert stdlib_only()
    print("diff-36 OK: circular-range-add")


if __name__ == "__main__":
    main()
