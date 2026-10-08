"""Modular Range Add: difference array example.

Range adds modulo m: values wrap around, e.g. Caesar-style shifts mod 26 over numeric positions.

What this IS: a real modular difference array, fail-closed on bad input
What this IS NOT: applying the modulo per update instead of at read
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_46_VERSION = "modular-range-add.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-modular-range-add.v1"


class DiffError(Exception):
    """Fail-closed."""


class ModDiff:
    """Range add modulo m. Fail-closed on bad bounds or modulus."""

    def __init__(self, n: int, m: int):
        if n <= 0 or m <= 1:
            raise DiffError("need n > 0 and m > 1")
        self.n = n
        self.m = m
        self._d = [0] * (n + 1)

    def add(self, l: int, r: int, v: int) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._d[l] += v
        self._d[r + 1] -= v

    def build(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            cur += self._d[i]
            out.append(cur % self.m)
        return out

def test_wrap():
    m = ModDiff(4, 26)
    m.add(0, 3, 25)
    m.add(0, 0, 3)
    assert m.build() == [2, 25, 25, 25]


def test_negative():
    m = ModDiff(3, 26)
    m.add(1, 2, -1)
    assert m.build() == [0, 25, 25]


def test_no_adds():
    m = ModDiff(2, 10)
    assert m.build() == [0, 0]


def test_bad():
    try:
        ModDiff(0, 26)
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
    test_negative()
    test_no_adds()
    test_bad()
    assert stdlib_only()
    print("diff-46 OK: modular-range-add")


if __name__ == "__main__":
    main()
