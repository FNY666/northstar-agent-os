"""Smallest Number in Infinite Set: pop the smallest positive int, with add-back support IS: min-heap of added-back numbers plus a running counter IS NOT: a sorted set of all positive ints"""

from __future__ import annotations

import ast
import heapq

VERSION = "heap-39.v1"

class SmallestInfiniteSet:
    """Infinite set {1, 2, 3, ...} with add-back.

    Fail-closed: ``add_back`` accepts only positive ints, else
    :class:`ValueError`; ``pop_smallest`` never fails.
    """

    def __init__(self) -> None:
        self._next = 1
        self._heap = []
        self._in_heap = set()

    def pop_smallest(self):
        if self._heap:
            val = heapq.heappop(self._heap)
            self._in_heap.discard(val)
            return val
        val = self._next
        self._next += 1
        return val

    def add_back(self, num) -> None:
        if isinstance(num, bool) or not isinstance(num, int) or num < 1:
            raise ValueError("num must be a positive int")
        if num < self._next and num not in self._in_heap:
            heapq.heappush(self._heap, num)
            self._in_heap.add(num)

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
    s = SmallestInfiniteSet()
    assert s.pop_smallest() == 1
    assert s.pop_smallest() == 2
    s.add_back(1)
    assert s.pop_smallest() == 1
    assert s.pop_smallest() == 3
    s.add_back(99)
    assert s.pop_smallest() == 4
    try:
        s.add_back(0)
    except ValueError:
        pass
    else:
        raise AssertionError("num=0 must raise ValueError")
    assert stdlib_only()
    print("heap-39.v1 OK")


if __name__ == "__main__":
    main()
