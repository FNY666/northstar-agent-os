"""DS: R-Tree (36/50). R-tree (spatial index)

Mock: node splitting and MBR hierarchy are stubbed; rectangle intersection queries run brute-force over a list, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast

#: Module version.
DS_36_VERSION = "ds-36-rtree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-36.rtree.v1"


class RTree:
    """API-compatible R-tree stub (see module docstring)."""

    def __init__(self):
        self._rects = []

    def insert(self, rid, bounds):
        """Insert rectangle ``bounds`` = (x1, y1, x2, y2) with id ``rid``."""
        x1, y1, x2, y2 = bounds
        if not (x1 <= x2 and y1 <= y2):
            raise ValueError("bad bounds")
        self._rects.append((rid, bounds))

    def query(self, bounds):
        """Return ids of rectangles intersecting ``bounds``."""
        x1, y1, x2, y2 = bounds
        out = []
        for rid, (a1, b1, a2, b2) in self._rects:
            if a1 <= x2 and a2 >= x1 and b1 <= y2 and b2 >= y1:
                out.append(rid)
        return out

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
    rt = RTree()
    rt.insert("a", (0, 0, 2, 2))
    rt.insert("b", (5, 5, 7, 7))
    assert rt.query((1, 1, 6, 6)) == ["a", "b"]
    assert rt.query((3, 3, 4, 4)) == []
    assert len(rt) == 2
    assert stdlib_only()
    print("ds-36 OK: rectangle intersection queries")


if __name__ == "__main__":
    main()
