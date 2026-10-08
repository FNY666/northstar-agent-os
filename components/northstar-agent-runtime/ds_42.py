"""DS: VP-Tree (42/50). vantage-point tree

Mock: vantage-point partitioning is stubbed; nearest-neighbor queries run brute-force, so semantics are correct but O(n) per query."""
from __future__ import annotations

import ast

#: Module version.
DS_42_VERSION = "ds-42-vp-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-42.vp-tree.v1"


class VPTree:
    """API-compatible VP-tree stub (see module docstring)."""

    def __init__(self, dist):
        self._dist = dist
        self._points = []

    def build(self, points):
        self._points = list(points)

    def insert(self, point):
        self._points.append(point)

    def nearest(self, query):
        """Return the nearest point (None if empty)."""
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
    def d(a, b):
            return abs(a - b)
    t = VPTree(d)
    t.build([1, 5, 9, 20])
    assert t.nearest(6) == 5
    assert t.nearest(19) == 20
    t.insert(4)
    assert t.nearest(4) == 4
    assert VPTree(d).nearest(1) is None
    assert stdlib_only()
    print("ds-42 OK: nearest neighbor, brute-force backend")


if __name__ == "__main__":
    main()
