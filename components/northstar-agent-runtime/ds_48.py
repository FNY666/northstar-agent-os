"""DS: SS-Tree (48/50). SS-tree (sphere index)

Mock: sphere hierarchy is stubbed; sphere overlap queries run brute-force over a list, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast
import math

#: Module version.
DS_48_VERSION = "ds-48-sstree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-48.sstree.v1"


class SSTree:
    """API-compatible SS-tree stub (see module docstring)."""

    def __init__(self):
        self._spheres = []

    def insert(self, sid, center, radius):
        if radius < 0:
            raise ValueError("radius must be non-negative")
        self._spheres.append((sid, tuple(center), radius))

    def query_point(self, point):
        """Return ids of spheres containing ``point``."""
        out = []
        for sid, center, radius in self._spheres:
            d = math.sqrt(sum((a - b) ** 2 for a, b in zip(center, point)))
            if d <= radius:
                out.append(sid)
        return out

    def __len__(self):
        return len(self._spheres)

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
    t = SSTree()
    t.insert("s1", (0, 0), 5)
    t.insert("s2", (20, 20), 2)
    assert t.query_point((3, 4)) == ["s1"]
    assert t.query_point((100, 100)) == []
    assert stdlib_only()
    print("ds-48 OK: sphere containment, brute-force")


if __name__ == "__main__":
    main()
