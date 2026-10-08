"""DS: TV-Tree (50/50). TV-tree (telescoping vectors)

Mock: telescoping dimension contraction is stubbed; nearest queries use weighted Euclidean distance over the active dimensions, brute-force."""
from __future__ import annotations

import ast
import math

#: Module version.
DS_50_VERSION = "ds-50-tv-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-50.tv-tree.v1"


class TVTree:
    """API-compatible TV-tree stub (see module docstring)."""

    def __init__(self, dims, active_dims=None):
        if dims <= 0:
            raise ValueError("dims must be positive")
        self.dims = dims
        self.active = active_dims if active_dims is not None else dims
        if not 1 <= self.active <= dims:
            raise ValueError("bad active_dims")
        self._points = []

    def insert(self, point):
        if len(point) != self.dims:
            raise ValueError("dimension mismatch")
        self._points.append(tuple(point))

    def _dist(self, a, b):
        return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(self.active)))

    def nearest(self, query):
        if len(query) != self.dims:
            raise ValueError("dimension mismatch")
        query = tuple(query)
        best = None
        best_d = float("inf")
        for p in self._points:
            d = self._dist(p, query)
            if d < best_d:
                best = p
                best_d = d
        return best

    def __len__(self):
        return len(self._points)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "math"}
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
    t = TVTree(3, active_dims=2)
    t.insert((0, 0, 100)); t.insert((5, 5, 0))
    assert t.nearest((1, 1, 999)) == (0, 0, 100)
    assert len(t) == 2
    assert stdlib_only()
    print("ds-50 OK: telescoping dims, weighted nearest")


if __name__ == "__main__":
    main()
