"""DS: X-Tree (47/50). X-tree (spatial index)

Mock: supernode handling and forced reinsertion are stubbed; rectangle queries run brute-force over a list, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast

#: Module version.
DS_47_VERSION = "ds-47-xtree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-47.xtree.v1"


class XTree:
    """API-compatible X-tree stub (see module docstring)."""

    def __init__(self):
        self._rects = []

    def insert(self, rid, bounds):
        x1, y1, x2, y2 = bounds
        if not (x1 <= x2 and y1 <= y2):
            raise ValueError("bad bounds")
        self._rects.append((rid, bounds))

    def query(self, bounds):
        x1, y1, x2, y2 = bounds
        return [rid for rid, (a1, b1, a2, b2) in self._rects
                if a1 <= x2 and a2 >= x1 and b1 <= y2 and b2 >= y1]

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
    t = XTree()
    t.insert("r1", (0, 0, 5, 5))
    t.insert("r2", (10, 10, 15, 15))
    assert t.query((4, 4, 11, 11)) == ["r1", "r2"]
    assert t.query((6, 6, 9, 9)) == []
    assert stdlib_only()
    print("ds-47 OK: rectangle overlap, brute-force")


if __name__ == "__main__":
    main()
