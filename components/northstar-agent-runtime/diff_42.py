"""Float Range Add: difference array example.

Difference array over floats: range adds of fractional values with exact prefix reconstruction.

What this IS: a real float difference array, fail-closed on bad bounds
What this IS NOT: rounding values to integers
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_42_VERSION = "float-range-add.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-float-range-add.v1"


class DiffError(Exception):
    """Fail-closed."""


class FloatDiff:
    """Float range adds. Fail-closed on bad bounds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._d = [0.0] * (n + 1)

    def add(self, l: int, r: int, v: float) -> None:
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._d[l] += v
        self._d[r + 1] -= v

    def build(self) -> list:
        out = []
        cur = 0.0
        for i in range(self.n):
            cur += self._d[i]
            out.append(cur)
        return out

def test_basic():
    f = FloatDiff(3)
    f.add(0, 1, 1.5)
    f.add(1, 2, 2.5)
    got = f.build()
    assert all(abs(a - b) < 1e-9 for a, b in zip(got, [1.5, 4.0, 2.5]))


def test_negative():
    f = FloatDiff(2)
    f.add(0, 1, -0.5)
    got = f.build()
    assert all(abs(a - b) < 1e-9 for a, b in zip(got, [-0.5, -0.5]))


def test_no_adds():
    f = FloatDiff(2)
    assert f.build() == [0.0, 0.0]


def test_bad():
    f = FloatDiff(2)
    try:
        f.add(0, 2, 1.0)
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
    test_negative()
    test_no_adds()
    test_bad()
    assert stdlib_only()
    print("diff-42 OK: float-range-add")


if __name__ == "__main__":
    main()
