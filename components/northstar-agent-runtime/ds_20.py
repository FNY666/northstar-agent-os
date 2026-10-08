"""DS: Bag (20/50). bag (dict-based multiset)"""
from __future__ import annotations

import ast

#: Module version.
DS_20_VERSION = "ds-20-bag.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-20.bag.v1"


class Bag:
    """Unordered bag: dict-based multiset without Counter."""

    def __init__(self):
        self._data = {}

    def add(self, value):
        self._data[value] = self._data.get(value, 0) + 1

    def remove(self, value):
        count = self._data.get(value, 0)
        if count == 0:
            raise ValueError("value not in bag")
        if count == 1:
            del self._data[value]
        else:
            self._data[value] = count - 1

    def count(self, value):
        return self._data.get(value, 0)

    def distinct(self):
        return len(self._data)

    def total(self):
        return sum(self._data.values())

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
    b = Bag()
    b.add("x"); b.add("x"); b.add("y")
    assert b.count("x") == 2
    assert b.distinct() == 2
    assert b.total() == 3
    b.remove("x")
    assert b.count("x") == 1
    assert stdlib_only()
    print("ds-20 OK: dict-based multiplicities")


if __name__ == "__main__":
    main()
