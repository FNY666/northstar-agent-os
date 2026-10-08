"""Brick Wall Least Crossed: difference array example.

LeetCode 554: rows of brick widths; count internal edge positions with a frequency map (event counting, sweep-line style); least crossed = rows - max.

What this IS: real internal-edge frequency counting, fail-closed on non-positive widths
What this IS NOT: drawing the wall and scanning each column
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_19_VERSION = "brick-wall-edges.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-brick-wall-edges.v1"


class DiffError(Exception):
    """Fail-closed."""


def least_bricks(wall: list) -> int:
    """wall: list of rows, each a list of positive widths."""
    if not wall:
        raise DiffError("wall must be non-empty")
    edge_counts = {}
    for row in wall:
        if not row or any(w <= 0 for w in row):
            raise DiffError("widths must be positive")
        pos = 0
        for w in row[:-1]:
            pos += w
            edge_counts[pos] = edge_counts.get(pos, 0) + 1
    if not edge_counts:
        return len(wall)
    return len(wall) - max(edge_counts.values())

def test_example():
    wall = [[1, 2, 2, 1], [3, 1, 2], [1, 3, 2], [2, 4], [3, 1, 2], [1, 3, 1, 1]]
    assert least_bricks(wall) == 2


def test_no_edges():
    assert least_bricks([[1], [1], [1]]) == 3


def test_single_row():
    assert least_bricks([[1, 2, 3]]) == 0


def test_bad_width():
    try:
        least_bricks([[1, 0, 2]])
    except DiffError:
        return
    raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
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
    test_example()
    test_no_edges()
    test_single_row()
    test_bad_width()
    assert stdlib_only()
    print("diff-19 OK: brick-wall-edges")


if __name__ == "__main__":
    main()
