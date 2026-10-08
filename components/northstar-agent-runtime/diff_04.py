"""Flight Bookings Totals: difference array example.

LeetCode 1109: bookings (first, last, seats) 1-indexed inclusive; total seats per flight via a difference array.

What this IS: the real O(n+q) booking aggregation, fail-closed on bad bookings
What this IS NOT: a per-flight simulation loop
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_04_VERSION = "flight-bookings.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-flight-bookings.v1"


class DiffError(Exception):
    """Fail-closed."""


def flight_bookings(bookings: list, n: int) -> list:
    """bookings: list of (first, last, seats), 1-indexed inclusive."""
    if n <= 0:
        raise DiffError("n must be > 0")
    diff = [0] * (n + 1)
    for first, last, seats in bookings:
        if not (1 <= first <= last <= n) or seats < 0:
            raise DiffError("bad booking")
        diff[first - 1] += seats
        diff[last] -= seats
    out = []
    cur = 0
    for i in range(n):
        cur += diff[i]
        out.append(cur)
    return out

def test_example():
    assert flight_bookings([[1, 2, 10], [2, 3, 20], [2, 5, 25]], 5) == [10, 55, 45, 25, 25]


def test_single():
    assert flight_bookings([[1, 2, 10], [2, 2, 15]], 2) == [10, 25]


def test_no_bookings():
    assert flight_bookings([], 3) == [0, 0, 0]


def test_bad_booking():
    try:
        flight_bookings([[0, 2, 10]], 5)
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
    test_single()
    test_no_bookings()
    test_bad_booking()
    assert stdlib_only()
    print("diff-04 OK: flight-bookings")


if __name__ == "__main__":
    main()
