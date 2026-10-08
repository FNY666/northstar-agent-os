"""DS: Bitset (21/50). fixed-size bitset"""
from __future__ import annotations

import ast

#: Module version.
DS_21_VERSION = "ds-21-bitset.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-21.bitset.v1"


class Bitset:
    """Fixed-size bitset backed by a Python int."""

    def __init__(self, size):
        if size <= 0:
            raise ValueError("size must be positive")
        self._size = size
        self._bits = 0

    def _check(self, index):
        if not 0 <= index < self._size:
            raise IndexError("bit index out of range")

    def set(self, index):
        self._check(index)
        self._bits |= 1 << index

    def clear(self, index):
        self._check(index)
        self._bits &= ~(1 << index)

    def test(self, index):
        self._check(index)
        return bool(self._bits & (1 << index))

    def count(self):
        return bin(self._bits).count("1")

    def __len__(self):
        return self._size

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
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
    b = Bitset(8)
    b.set(0); b.set(7)
    assert b.test(0) is True
    assert b.test(3) is False
    assert b.count() == 2
    b.clear(0)
    assert b.test(0) is False
    assert len(b) == 8
    assert stdlib_only()
    print("ds-21 OK: set/clear/test/count")


if __name__ == "__main__":
    main()
