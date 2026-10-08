"""DS: Ball Tree (45/50). ball tree

Mock: ball partitioning is stubbed; radius and nearest queries run brute-force, so semantics are correct but O(n) per query."""
from __future__ import annotations

import ast

#: Module version.
DS_45_VERSION = "ds-45-ball-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-45.ball-tree.v1"


class BallTree:
    """API-compatible ball-tree stub (see module docstring)."""

    def __init__(self, dist):
        self._dist = dist
        self._points = []

    def build(self, points):
        self._points = list(points)

    def query_radius(self, query, radius):
        if radius < 0:
            raise ValueError("radius must be non-negative")
        return [p for p in self._points if self._dist(p, query) <= radius]

    def nearest(self, query):
        best = None
        best_d = float("inf")
        for p in self._points:
            d = self._dist(p, query)
            if d < best_d:
                best = p
                best_d = d
        return best

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
    t = BallTree(lambda a, b: abs(a - b))
    t.build([1, 5, 10, 20])
    assert sorted(t.query_radius(6, 5)) == [1, 5, 10]
    assert t.nearest(19) == 20
    assert stdlib_only()
    print("ds-45 OK: radius/nearest queries, brute-force")


if __name__ == "__main__":
    main()
