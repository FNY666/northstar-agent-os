"""Shear sort: 2D mesh row/column shear phases.

Lays the input on a rows x cols mesh; each phase sorts rows (alternating direction) then columns; after ceil(log2(rows)) + 1 phases the mesh reads sorted in snake order.

What this IS: a real 2D mesh sorting algorithm with O(log n) parallel phases.

What this IS NOT:
* Needs a near-square mesh; padding with +inf fills it.
* Sequentially it is just O(n log n) with extra steps.
"""

from __future__ import annotations

import ast
import math
from typing import List

#: Module version.
SORT_40_VERSION = "sort-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-40.v1"


def sort(data: List[int]) -> List[int]:
    # Shear sort: lay the input on a rows x cols mesh; alternate
    # sorting rows (alternating direction) and columns for
    # ceil(log2(rows)) + 1 phases; read back in snake order.
    a = list(data)
    n = len(a)
    if n <= 1:
        return a
    rows = max(1, math.isqrt(n))
    cols = (n + rows - 1) // rows
    inf = float("inf")
    flat = a + [inf] * (rows * cols - n)
    grid = [flat[r * cols:(r + 1) * cols] for r in range(rows)]
    phases = 0
    while (1 << phases) < rows:
        phases += 1
    for _ in range(phases + 1):
        for r in range(rows):
            grid[r] = sorted(grid[r], reverse=(r % 2 == 1))
        for c in range(cols):
            col = sorted(grid[r][c] for r in range(rows))
            for r in range(rows):
                grid[r][c] = col[r]
    out: List[int] = []
    for r in range(rows):
        out.extend(grid[r] if r % 2 == 0 else grid[r][::-1])
    return [x for x in out if x != inf]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
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
    assert sort([]) == []
    assert sort([1]) == [1]
    assert sort([3, 1, 2]) == [1, 2, 3]
    assert sort([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    assert sort([-3, 0, -1, 2]) == [-3, -1, 0, 2]
    assert sort([2, 2, 1, 1]) == [1, 1, 2, 2]
    assert stdlib_only()
    print("shear OK")


if __name__ == "__main__":
    main()
