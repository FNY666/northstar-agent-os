"""Car Pooling Feasibility: difference array example.

LeetCode 1094: trips (passengers, start, end) with end exclusive; check capacity is never exceeded via a difference sweep.

What this IS: a real O(max_stop + trips) capacity check, fail-closed on bad trips
What this IS NOT: a minute-by-minute simulation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_05_VERSION = "car-pooling.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-car-pooling.v1"


class DiffError(Exception):
    """Fail-closed."""


def car_pooling(trips: list, capacity: int) -> bool:
    """trips: list of (passengers, start, end), end exclusive."""
    if capacity < 0:
        raise DiffError("capacity must be >= 0")
    diff = [0] * 1002
    for p, s, e in trips:
        if not (0 <= s < e <= 1000) or p < 0:
            raise DiffError("bad trip")
        diff[s] += p
        diff[e] -= p
    cur = 0
    for v in diff:
        cur += v
        if cur > capacity:
            return False
    return True

def test_over_capacity():
    assert car_pooling([[2, 1, 5], [3, 3, 7]], 4) is False


def test_fits():
    assert car_pooling([[2, 1, 5], [3, 3, 7]], 5) is True


def test_no_trips():
    assert car_pooling([], 1) is True


def test_bad_trip():
    try:
        car_pooling([[2, 5, 5]], 4)
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
    test_over_capacity()
    test_fits()
    test_no_trips()
    test_bad_trip()
    assert stdlib_only()
    print("diff-05 OK: car-pooling")


if __name__ == "__main__":
    main()
