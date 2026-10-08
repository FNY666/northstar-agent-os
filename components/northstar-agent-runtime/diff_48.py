"""Epoch Reset Difference Array: difference array example.

Difference array with O(1) reset via a generation counter: stale cells are lazily cleared on touch.

What this IS: a real generation-guarded difference array, fail-closed on bad bounds
What this IS NOT: zeroing the whole array on reset
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_48_VERSION = "epoch-reset-diff.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-epoch-reset-diff.v1"


class DiffError(Exception):
    """Fail-closed."""


class EpochDiff:
    """Difference array with O(1) reset via generations."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._d = [0] * (n + 1)
        self._gen = [0] * (n + 1)
        self._cur = 1

    def reset(self) -> None:
        self._cur += 1

    def _touch(self, i: int) -> None:
        if self._gen[i] != self._cur:
            self._gen[i] = self._cur
            self._d[i] = 0

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._touch(l)
        self._touch(r + 1)
        self._d[l] += v
        self._d[r + 1] -= v

    def build(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            self._touch(i)
            cur += self._d[i]
            out.append(cur)
        return out

def test_basic():
    e = EpochDiff(4)
    e.add(0, 2, 5)
    assert e.build() == [5, 5, 5, 0]


def test_reset():
    e = EpochDiff(4)
    e.add(0, 2, 5)
    e.reset()
    assert e.build() == [0, 0, 0, 0]
    e.add(1, 1, 9)
    assert e.build() == [0, 9, 0, 0]


def test_double_reset():
    e = EpochDiff(2)
    e.reset()
    e.reset()
    assert e.build() == [0, 0]


def test_bad():
    e = EpochDiff(2)
    try:
        e.add(0, 2, 1)
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
    test_reset()
    test_double_reset()
    test_bad()
    assert stdlib_only()
    print("diff-48 OK: epoch-reset-diff")


if __name__ == "__main__":
    main()
