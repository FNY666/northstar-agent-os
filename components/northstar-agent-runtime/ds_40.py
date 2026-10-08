"""DS: Interval Tree (40/50). interval tree

Mock: centered interval-tree structure is stubbed; overlap queries run over a list, so semantics are correct but O(n) per query."""
from __future__ import annotations

import ast

#: Module version.
DS_40_VERSION = "ds-40-interval-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-40.interval-tree.v1"


class IntervalTree:
    """API-compatible interval-tree stub (see module docstring)."""

    def __init__(self):
        self._intervals = []

    def insert(self, lo, hi, data=None):
        if lo > hi:
            raise ValueError("lo must be <= hi")
        self._intervals.append((lo, hi, data))

    def query_point(self, x):
        """Return intervals containing point ``x``."""
        return [(lo, hi, d) for (lo, hi, d) in self._intervals
                if lo <= x <= hi]

    def query_overlap(self, lo, hi):
        """Return intervals overlapping [lo, hi]."""
        return [(a, b, d) for (a, b, d) in self._intervals
                if a <= hi and b >= lo]

    def __len__(self):
        return len(self._intervals)

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
    t = IntervalTree()
    t.insert(1, 5, "a"); t.insert(4, 8, "b"); t.insert(10, 12, "c")
    assert len(t.query_point(4)) == 2
    assert t.query_point(9) == []
    assert len(t.query_overlap(5, 11)) == 3
    assert stdlib_only()
    print("ds-40 OK: point/overlap queries, list backend")


if __name__ == "__main__":
    main()
