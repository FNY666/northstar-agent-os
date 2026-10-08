"""DS: Priority Queue (08/50). heap-based priority queue"""
from __future__ import annotations

import ast
import heapq
import itertools

#: Module version.
DS_08_VERSION = "ds-08-priority-queue.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-08.priority-queue.v1"


class PriorityQueue:
    """Min-priority queue; ties break FIFO via a sequence counter."""

    def __init__(self):
        self._heap = []
        self._count = itertools.count()

    def push(self, priority, item):
        heapq.heappush(self._heap, (priority, next(self._count), item))

    def pop(self):
        if not self._heap:
            raise IndexError("empty")
        return heapq.heappop(self._heap)[2]

    def peek(self):
        if not self._heap:
            raise IndexError("empty")
        return self._heap[0][2]

    def __len__(self):
        return len(self._heap)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "heapq", "itertools"}
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
    pq = PriorityQueue()
    pq.push(3, "low"); pq.push(1, "high"); pq.push(2, "mid")
    assert pq.peek() == "high"
    assert pq.pop() == "high"
    assert pq.pop() == "mid"
    assert pq.pop() == "low"
    assert stdlib_only()
    print("ds-08 OK: min-priority with FIFO tie-break")


if __name__ == "__main__":
    main()
