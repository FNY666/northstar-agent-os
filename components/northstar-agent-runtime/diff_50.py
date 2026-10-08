"""Booking Capacity Validator: difference array example.

Composite: bookings (start, end, seats) half-open against a capacity; returns (feasible, peak_load) from one sparse difference sweep.

What this IS: a real composite feasibility validator, fail-closed on bad bookings
What this IS NOT: validating bookings one at a time
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_50_VERSION = "booking-capacity-validator.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-booking-capacity-validator.v1"


class DiffError(Exception):
    """Fail-closed."""


def validate_bookings(bookings: list, capacity: int) -> tuple:
    """Returns (feasible, peak_load)."""
    if capacity < 0:
        raise DiffError("capacity must be >= 0")
    d = {}
    for s, e, seats in bookings:
        if not (s < e) or seats < 0:
            raise DiffError("bad booking")
        d[s] = d.get(s, 0) + seats
        d[e] = d.get(e, 0) - seats
    cur = 0
    peak = 0
    for k in sorted(d):
        cur += d[k]
        if cur > peak:
            peak = cur
    return peak <= capacity, peak

def test_over():
    assert validate_bookings([(1, 5, 10), (2, 6, 20)], 25) == (False, 30)


def test_fits():
    assert validate_bookings([(1, 5, 10), (2, 6, 20)], 30) == (True, 30)


def test_empty():
    assert validate_bookings([], 0) == (True, 0)


def test_bad():
    try:
        validate_bookings([(5, 5, 1)], 10)
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
    print("diff-50 OK: booking-capacity-validator")


if __name__ == "__main__":
    main()
