"""Booking Counter Timeline: difference array example.

Add [start, end) bookings; query how many are active at time t and the peak concurrency, via a sparse difference map.

What this IS: a real sparse booking ledger with active-at and peak queries, fail-closed on bad bookings
What this IS NOT: scanning all bookings per query
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_16_VERSION = "booking-counter.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-booking-counter.v1"


class DiffError(Exception):
    """Fail-closed."""


class BookingCounter:
    """Sparse difference ledger for half-open bookings."""

    def __init__(self):
        self._diff = {}

    def book(self, start: int, end: int) -> None:
        if not (start < end):
            raise DiffError("need start < end")
        self._diff[start] = self._diff.get(start, 0) + 1
        self._diff[end] = self._diff.get(end, 0) - 1

    def active_at(self, t: int) -> int:
        cur = 0
        for k in sorted(self._diff):
            if k > t:
                break
            cur += self._diff[k]
        return cur

    def peak(self) -> int:
        cur = 0
        best = 0
        for k in sorted(self._diff):
            cur += self._diff[k]
            if cur > best:
                best = cur
        return best

def test_active():
    b = BookingCounter()
    b.book(1, 5)
    b.book(2, 6)
    b.book(8, 10)
    assert b.active_at(3) == 2
    assert b.active_at(7) == 0
    assert b.active_at(9) == 1


def test_peak():
    b = BookingCounter()
    b.book(1, 5)
    b.book(2, 6)
    assert b.peak() == 2


def test_empty():
    b = BookingCounter()
    assert b.active_at(0) == 0
    assert b.peak() == 0


def test_bad_book():
    b = BookingCounter()
    try:
        b.book(5, 5)
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
    test_active()
    test_peak()
    test_empty()
    test_bad_book()
    assert stdlib_only()
    print("diff-16 OK: booking-counter")


if __name__ == "__main__":
    main()
