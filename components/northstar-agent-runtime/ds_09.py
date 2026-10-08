"""DS: Binary Heap (09/50). min-heap"""
from __future__ import annotations

import ast
import heapq

#: Module version.
DS_09_VERSION = "ds-09-heap.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-09.heap.v1"


class MinHeap:
    """Binary min-heap backed by heapq."""

    def __init__(self, data=()):
        self._heap = list(data)
        heapq.heapify(self._heap)

    def push(self, value):
        heapq.heappush(self._heap, value)

    def pop(self):
        if not self._heap:
            raise IndexError("empty")
        return heapq.heappop(self._heap)

    def peek(self):
        if not self._heap:
            raise IndexError("empty")
        return self._heap[0]

    def __len__(self):
        return len(self._heap)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "heapq"}
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
    h = MinHeap([5, 3, 8, 1])
    assert h.peek() == 1
    h.push(0)
    assert [h.pop(), h.pop(), h.pop()] == [0, 1, 3]
    assert len(h) == 2
    assert stdlib_only()
    print("ds-09 OK: heapify/push/pop/peek")


if __name__ == "__main__":
    main()
