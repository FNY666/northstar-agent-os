"""Strict Decrement Ledger: difference array example.

A decrement-only ledger with positive magnitude API: decrement(l, r, v) subtracts v; zero or negative magnitudes are rejected fail-closed.

What this IS: a real magnitude-based decrement ledger, fail-closed on bad input
What this IS NOT: a signed range-add structure
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_34_VERSION = "decrement-ledger.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-decrement-ledger.v1"


class DiffError(Exception):
    """Fail-closed."""


class DecrementLedger:
    """Decrement-only ledger. Fail-closed on bad magnitudes or bounds."""

    def __init__(self, n: int):
        if n <= 0:
            raise DiffError("n must be > 0")
        self.n = n
        self._d = [0] * (n + 1)

    def decrement(self, l: int, r: int, v: int) -> None:
        if v <= 0:
            raise DiffError("v must be positive")
        if not (0 <= l <= r < self.n):
            raise DiffError("bounds must satisfy 0 <= l <= r < n")
        self._d[l] -= v
        self._d[r + 1] += v

    def build(self) -> list:
        out = []
        cur = 0
        for i in range(self.n):
            cur += self._d[i]
            out.append(cur)
        return out

def test_basic():
    d = DecrementLedger(4)
    d.decrement(0, 2, 5)
    assert d.build() == [-5, -5, -5, 0]


def test_overlap():
    d = DecrementLedger(3)
    d.decrement(0, 2, 2)
    d.decrement(1, 1, 3)
    assert d.build() == [-2, -5, -2]


def test_zero_rejected():
    d = DecrementLedger(3)
    try:
        d.decrement(0, 1, 0)
    except DiffError:
        return
    raise AssertionError("expected DiffError")


def test_bad_bounds():
    d = DecrementLedger(3)
    try:
        d.decrement(0, 3, 1)
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
    test_zero_rejected()
    test_bad_bounds()
    assert stdlib_only()
    print("diff-34 OK: decrement-ledger")


if __name__ == "__main__":
    main()
