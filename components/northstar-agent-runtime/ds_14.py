"""DS: B-Tree (14/50). B-tree

Mock: node splitting/merging is stubbed; the ordered-map API is backed by a dict so all operations are correct."""
from __future__ import annotations

import ast

#: Module version.
DS_14_VERSION = "ds-14-btree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-14.btree.v1"


class BTree:
    """API-compatible B-tree stub (see module docstring)."""

    def __init__(self, order=4):
        if order < 3:
            raise ValueError("order must be >= 3")
        self.order = order
        self._data = {}

    def insert(self, key, value=None):
        self._data[key] = value

    def search(self, key):
        return self._data.get(key)

    def delete(self, key):
        if key in self._data:
            del self._data[key]
            return True
        return False

    def keys(self):
        return sorted(self._data.keys())

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
    t = BTree(order=4)
    for k in (5, 1, 9, 3):
        t.insert(k, k * 10)
    assert t.keys() == [1, 3, 5, 9]
    assert t.search(9) == 90
    assert t.delete(3) is True
    assert len(t) == 3
    assert stdlib_only()
    print("ds-14 OK: ordered-map API, dict backend")


if __name__ == "__main__":
    main()
