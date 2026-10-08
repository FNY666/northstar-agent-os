"""Capacity Feasibility Check: difference array example.

Tasks (start, end, demand) half-open; True iff demand never exceeds capacity, via a weighted sparse difference sweep.

What this IS: a real demand-vs-capacity sweep, fail-closed on bad tasks
What this IS NOT: simulating demand per time unit
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_33_VERSION = "capacity-feasible.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-capacity-feasible.v1"


class DiffError(Exception):
    """Fail-closed."""


def capacity_feasible(tasks: list, capacity: int) -> bool:
    """tasks: list of (start, end, demand). True iff demand <= capacity always."""
    if capacity < 0:
        raise DiffError("capacity must be >= 0")
    diff = {}
    for s, e, dem in tasks:
        if not (s < e) or dem < 0:
            raise DiffError("bad task")
        diff[s] = diff.get(s, 0) + dem
        diff[e] = diff.get(e, 0) - dem
    cur = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > capacity:
            return False
    return True

def test_over():
    assert capacity_feasible([(1, 3, 4), (2, 5, 4)], 7) is False


def test_fits():
    assert capacity_feasible([(1, 3, 4), (2, 5, 4)], 8) is True


def test_empty():
    assert capacity_feasible([], 0) is True


def test_bad():
    try:
        capacity_feasible([(3, 3, 1)], 5)
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
    test_over()
    test_fits()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-33 OK: capacity-feasible")


if __name__ == "__main__":
    main()
