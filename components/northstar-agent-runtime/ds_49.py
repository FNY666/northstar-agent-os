"""DS: SR-Tree (49/50). SR-tree (sphere-rectangle index)

Mock: sphere/rectangle hierarchy is stubbed; intersection queries run brute-force over a rectangle list, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast

#: Module version.
DS_49_VERSION = "ds-49-srtree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-49.srtree.v1"


class SRTree:
    """API-compatible SR-tree stub (see module docstring)."""

    def __init__(self):
        self._rects = []

    def insert(self, rid, bounds):
        x1, y1, x2, y2 = bounds
        if not (x1 <= x2 and y1 <= y2):
            raise ValueError("bad bounds")
        self._rects.append((rid, bounds))

    def query_rect(self, bounds):
        x1, y1, x2, y2 = bounds
        return [rid for rid, (a1, b1, a2, b2) in self._rects
                if a1 <= x2 and a2 >= x1 and b1 <= y2 and b2 >= y1]

    def query_sphere(self, center, radius):
        """Return ids whose rectangle intersects the sphere bounding box."""
        if radius < 0:
            raise ValueError("radius must be non-negative")
        cx, cy = center
        return self.query_rect((cx - radius, cy - radius,
                                cx + radius, cy + radius))

    def __len__(self):
        return len(self._rects)

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
    t = SRTree()
    t.insert("a", (0, 0, 4, 4))
    t.insert("b", (50, 50, 60, 60))
    assert t.query_rect((2, 2, 6, 6)) == ["a"]
    assert t.query_sphere((2, 2), 3) == ["a"]
    assert t.query_sphere((55, 55), 1) == ["b"]
    assert stdlib_only()
    print("ds-49 OK: rect/sphere queries, brute-force")


if __name__ == "__main__":
    main()
