"""Spaghetti sort (simulated): analog rod-length model simulation.

The analog version cuts a rod to length x per value and lets the rods fall in parallel; this simulates the process deterministically, stable by input index.

What this IS: a deterministic simulation of the parallel analog spaghetti sort.

What this IS NOT:
* Not the physical/parallel original -- no rods were harmed.
* The simulation is a stable sort by value.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_49_VERSION = "sort-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-49.v1"


def sort(data: List[int]) -> List[int]:
    # Spaghetti sort (simulation): the analog version cuts rods to
    # length x and lets them fall in parallel; this simulates the
    # process deterministically, stable by input index.
    indexed = sorted(((x, i) for i, x in enumerate(data)))
    return [x for x, _ in indexed]

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    print("spaghetti OK")


if __name__ == "__main__":
    main()
