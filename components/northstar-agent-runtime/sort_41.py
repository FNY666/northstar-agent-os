"""Sleep sort (simulated): timing-model simulation, no threads.

The threaded original sleeps x time units per value x so values 'wake' in order; this simulates that timing model deterministically, stable by input index, without spawning threads.

What this IS: a deterministic simulation of the sleep sort timing discipline.

What this IS NOT:
* Not the racy threaded original -- no timers or threads here.
* The simulation is just a stable sort by value; the point is the model.
"""

from __future__ import annotations

import ast
from typing import List

#: Module version.
SORT_41_VERSION = "sort-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.sort-41.v1"


def sort(data: List[int]) -> List[int]:
    # Sleep sort (simulation): the threaded original sleeps x time
    # units per value x, so values "wake" in order. This simulates
    # the timing model deterministically (stable by input index)
    # without spawning threads.
    a = list(data)
    if not a:
        return a
    lo = min(a)
    events = sorted(((x - lo, i, x) for i, x in enumerate(a)))
    return [x for _, _, x in events]

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
    print("sleep OK")


if __name__ == "__main__":
    main()
