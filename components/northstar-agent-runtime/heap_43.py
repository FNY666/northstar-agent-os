"""Seat Reservation Manager: reserve the smallest free seat, unreserve seats IS: min-heap of freed seats plus a running counter IS NOT: a sorted set of free seats"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-43.v1"

class SeatManager:
    """Reserve/unreserve seats numbered 1..n.

    Fail-closed: ``n >= 1`` and ``unreserve`` accepts only seats in
    range, else :class:`ValueError`.
    """

    def __init__(self, n) -> None:
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ValueError("n must be a positive int")
        self._next = 1
        self._n = n
        self._heap = []
        self._reserved = set()

    def reserve(self):
        if self._heap:
            seat = heapq.heappop(self._heap)
        elif self._next <= self._n:
            seat = self._next
            self._next += 1
        else:
            raise IndexError("no seats available")
        self._reserved.add(seat)
        return seat

    def unreserve(self, seat_number) -> None:
        if (isinstance(seat_number, bool) or not isinstance(seat_number, int)
                or not 1 <= seat_number <= self._n):
            raise ValueError("seat_number out of range")
        if seat_number in self._reserved:
            self._reserved.discard(seat_number)
            heapq.heappush(self._heap, seat_number)

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "heapq", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    sm = SeatManager(5)
    assert sm.reserve() == 1
    assert sm.reserve() == 2
    sm.unreserve(2)
    assert sm.reserve() == 2
    assert sm.reserve() == 3
    assert sm.reserve() == 4
    assert sm.reserve() == 5
    try:
        sm.reserve()
    except IndexError:
        pass
    else:
        raise AssertionError("full manager must raise IndexError")
    try:
        SeatManager(0)
    except ValueError:
        pass
    else:
        raise AssertionError("n=0 must raise ValueError")
    assert stdlib_only()
    print("heap-43.v1 OK")


if __name__ == "__main__":
    main()
