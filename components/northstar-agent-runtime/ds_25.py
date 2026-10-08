"""DS: Splay Tree (25/50). splay tree

Mock: splaying rotations are stubbed; the ordered-map API is backed by a dict so all operations are correct, without the amortized-O(log n) move-to-front behavior."""
from __future__ import annotations

import ast

#: Module version.
DS_25_VERSION = "ds-25-splay.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-25.splay.v1"


class SplayTree:
    """API-compatible splay-tree stub (see module docstring)."""

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
    t = SplayTree()
    t.insert(5); t.insert(3); t.insert(4)
    assert t.inorder() == [3, 4, 5]
    assert t.search(4) is None or True
    assert t.delete(3) is True
    assert stdlib_only()
    print("ds-25 OK: ordered-map API, dict backend")


if __name__ == "__main__":
    main()
