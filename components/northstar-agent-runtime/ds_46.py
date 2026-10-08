"""DS: M-Tree (46/50). M-tree (metric tree)

Mock: routing-object promotion/partitioning is stubbed; range queries run brute-force, so semantics are correct but O(n) per query."""
from __future__ import annotations

import ast

#: Module version.
DS_46_VERSION = "ds-46-mtree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-46.mtree.v1"


class MTree:
    """API-compatible M-tree stub (see module docstring)."""

    def __init__(self, dist):
        self._dist = dist
        self._entries = []

    def insert(self, obj):
        self._entries.append(obj)

    def range_query(self, query, radius):
        """Return entries within ``radius`` of ``query``."""
        if radius < 0:
            raise ValueError("radius must be non-negative")
        return [e for e in self._entries if self._dist(e, query) <= radius]

    def __len__(self):
        return len(self._entries)

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
    t = MTree(lambda a, b: abs(a - b))
    t.insert(1); t.insert(10); t.insert(25)
    assert t.range_query(12, 5) == [10]
    assert len(t) == 3
    assert stdlib_only()
    print("ds-46 OK: metric range queries, brute-force")


if __name__ == "__main__":
    main()
