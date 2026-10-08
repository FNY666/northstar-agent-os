"""DS: Hash Set (18/50). hash set"""
from __future__ import annotations

import ast

#: Module version.
DS_18_VERSION = "ds-18-set.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-18.set.v1"


class HashSet:
    """Hash set backed by the builtin set."""

    def __init__(self, items=()):
        self._data = set(items)

    def add(self, value):
        self._data.add(value)

    def discard(self, value):
        self._data.discard(value)

    def contains(self, value):
        return value in self._data

    def union(self, other):
        return HashSet(self._data | set(other))

    def intersection(self, other):
        return HashSet(self._data & set(other))

    def to_set(self):
        return set(self._data)

    def __len__(self):
        return len(self._data)

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
    s = HashSet([1, 2, 2, 3])
    assert len(s) == 3
    assert s.contains(2) is True
    s.discard(2)
    assert s.contains(2) is False
    assert s.union([3, 4]).to_set() == {1, 3, 4}
    assert s.intersection([1, 9]).to_set() == {1}
    assert stdlib_only()
    print("ds-18 OK: add/discard/union/intersection")


if __name__ == "__main__":
    main()
