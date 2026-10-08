"""DS: Queue (06/50). FIFO queue"""
from __future__ import annotations

import ast
import collections

#: Module version.
DS_06_VERSION = "ds-06-queue.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-06.queue.v1"


class Queue:
    """FIFO queue backed by collections.deque."""

    def __init__(self):
        self._data = collections.deque()

    def enqueue(self, value):
        self._data.append(value)

    def dequeue(self):
        if not self._data:
            raise IndexError("empty")
        return self._data.popleft()

    def peek(self):
        if not self._data:
            raise IndexError("empty")
        return self._data[0]

    def is_empty(self):
        return not self._data

    def __len__(self):
        return len(self._data)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "collections"}
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
    q = Queue()
    assert q.is_empty()
    q.enqueue(1); q.enqueue(2); q.enqueue(3)
    assert q.peek() == 1
    assert q.dequeue() == 1
    assert q.dequeue() == 2
    assert len(q) == 1
    assert stdlib_only()
    print("ds-06 OK: FIFO enqueue/dequeue/peek")


if __name__ == "__main__":
    main()
