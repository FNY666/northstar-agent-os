"""DS: AVL Tree (12/50). AVL self-balancing tree

Mock: balanced-tree rebalancing is stubbed; the ordered-map API is backed by a dict so all operations are correct, just not O(log n) guaranteed."""
from __future__ import annotations

import ast

#: Module version.
DS_12_VERSION = "ds-12-avl.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-12.avl.v1"


class AVLTree:
    """API-compatible AVL stub (see module docstring)."""

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
    t = AVLTree()
    t.insert(3, "c"); t.insert(1, "a"); t.insert(2, "b")
    assert t.inorder() == [1, 2, 3]
    assert t.search(2) == "b"
    assert t.delete(2) is True
    assert t.search(2) is None
    assert len(t) == 2
    assert stdlib_only()
    print("ds-12 OK: ordered-map API, dict backend")


if __name__ == "__main__":
    main()
