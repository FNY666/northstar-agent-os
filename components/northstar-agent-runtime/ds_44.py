"""DS: Cover Tree (44/50). cover tree

Mock: covering hierarchy is stubbed; nearest-neighbor queries run brute-force, so semantics are correct but O(n) per query."""
from __future__ import annotations

import ast

#: Module version.
DS_44_VERSION = "ds-44-cover-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-44.cover-tree.v1"


class CoverTree:
    """API-compatible cover-tree stub (see module docstring)."""

    def __init__(self, dist):
        self._dist = dist
        self._points = []

    def insert(self, point):
        self._points.append(point)

    def nearest(self, query):
        best = None
        best_d = float("inf")
        for p in self._points:
            d = self._dist(p, query)
            if d < best_d:
                best = p
                best_d = d
        return best

    def k_nearest(self, query, k):
        if k <= 0:
            raise ValueError("k must be positive")
        ranked = sorted(self._points, key=lambda p: self._dist(p, query))
        return ranked[:k]

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
    t = CoverTree(lambda a, b: abs(a - b))
    for p in (1, 10, 20, 30):
        t.insert(p)
    assert t.nearest(12) == 10
    assert t.k_nearest(12, 2) == [10, 20]
    assert stdlib_only()
    print("ds-44 OK: nearest/k-nearest, brute-force backend")


if __name__ == "__main__":
    main()
