"""DS: Treap (24/50). treap (randomized BST)

Mock: random priorities and rotations are stubbed; the ordered-map API is backed by a dict so all operations are correct."""
from __future__ import annotations

import ast

#: Module version.
DS_24_VERSION = "ds-24-treap.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-24.treap.v1"


class Treap:
    """API-compatible treap stub (see module docstring)."""

    def __init__(self):
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

    def inorder(self):
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
    t = Treap()
    t.insert(2, "b"); t.insert(1, "a")
    assert t.inorder() == [1, 2]
    assert t.search(1) == "a"
    assert t.delete(2) is True
    assert stdlib_only()
    print("ds-24 OK: ordered-map API, dict backend")


if __name__ == "__main__":
    main()
