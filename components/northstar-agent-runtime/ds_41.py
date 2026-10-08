"""DS: Range Tree (41/50). range tree (1D)

Mock: fractional cascading and 2D structure are stubbed; 1D range queries run on a sorted list via bisect, so semantics are correct."""
from __future__ import annotations

import ast
import bisect

#: Module version.
DS_41_VERSION = "ds-41-range-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-41.range-tree.v1"


class RangeTree:
    """Simplified 1D range tree (see module docstring)."""

    def __init__(self, points=()):
        self._points = sorted(points)

    def insert(self, x):
        bisect.insort(self._points, x)

    def query(self, lo, hi):
        """Return points in [lo, hi]."""
        if lo > hi:
            raise ValueError("lo must be <= hi")
        l = bisect.bisect_left(self._points, lo)
        r = bisect.bisect_right(self._points, hi)
        return self._points[l:r]

    def __len__(self):
        return len(self._points)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "bisect"}
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
    t = RangeTree([5, 1, 9, 3, 7])
    assert t.query(2, 8) == [3, 5, 7]
    t.insert(4)
    assert t.query(2, 8) == [3, 4, 5, 7]
    assert t.query(10, 20) == []
    assert stdlib_only()
    print("ds-41 OK: 1D range queries via bisect")


if __name__ == "__main__":
    main()
