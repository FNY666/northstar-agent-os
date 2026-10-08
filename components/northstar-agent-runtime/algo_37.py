"""Binary min-heap with manually implemented sift up/down.

A min-heap is a complete binary tree stored in a list where every
parent <= its children, so the minimum is always at index 0.

Complexities: push O(log n), pop O(log n), peek O(1). Both sift-up
(insert) and sift-down (extract-min) are implemented by hand here;
heapq is deliberately not used for the core logic.
"""

from __future__ import annotations

import ast
import sys
from typing import Any, List

ALGO_37_VERSION = "algo-37.v1"


class MinHeap:
    """Min-heap with manual sift up/down."""

    def __init__(self) -> None:
        self._data: List[Any] = []

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return bool(self._data)

    def push(self, x: Any) -> None:
        """Insert x, O(log n)."""
        data = self._data
        data.append(x)
        i = len(data) - 1
        while i > 0:
            parent = (i - 1) // 2
            if data[i] < data[parent]:
                data[i], data[parent] = data[parent], data[i]
                i = parent
            else:
                break

    def peek(self) -> Any:
        """Return the smallest element without removing it, O(1)."""
        if not self._data:
            raise IndexError("peek from empty heap")
        return self._data[0]

    def pop(self) -> Any:
        """Remove and return the smallest element, O(log n)."""
        data = self._data
        if not data:
            raise IndexError("pop from empty heap")
        smallest = data[0]
        last = data.pop()
        if data:
            data[0] = last
            self._sift_down(0)
        return smallest

    def _sift_down(self, i: int) -> None:
        data = self._data
        n = len(data)
        while True:
            left = 2 * i + 1
            right = 2 * i + 2
            smallest = i
            if left < n and data[left] < data[smallest]:
                smallest = left
            if right < n and data[right] < data[smallest]:
                smallest = right
            if smallest == i:
                return
            data[i], data[smallest] = data[smallest], data[i]
            i = smallest


def stdlib_only() -> bool:
    """Assert every imported top-level module is from the stdlib."""
    src = open(__file__, encoding="utf-8").read()
    tree = ast.parse(src)
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module
    return True


def main() -> None:
    h = MinHeap()
    assert len(h) == 0
    try:
        h.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
    for x in [5, 3, 8, 1, 9, 2, 7]:
        h.push(x)
    assert len(h) == 7
    assert h.peek() == 1
    assert [h.pop() for _ in range(7)] == [1, 2, 3, 5, 7, 8, 9]
    assert len(h) == 0
    # Duplicates stay ordered.
    h2 = MinHeap()
    for x in [4, 4, 1, 1, 4]:
        h2.push(x)
    assert [h2.pop() for _ in range(5)] == [1, 1, 4, 4, 4]
    # Single element.
    h3 = MinHeap()
    h3.push(42)
    assert h3.peek() == 42
    assert h3.pop() == 42
    assert len(h3) == 0
    assert stdlib_only()
    print("algo_37 OK")


if __name__ == "__main__":
    main()
