"""ArrayQueue: FIFO queue on a list with a head index and periodic compaction. IS: an amortized O(1) FIFO queue; dequeue/peek on empty raise IndexError. IS NOT: a thread-safe, blocking, or persistence-backed queue."""

from __future__ import annotations

import ast
from typing import Any, List
VERSION = "queue-01.v1"

def _req_nonneg_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int")
    return value


class ArrayQueue:
    """FIFO queue backed by a list plus a head pointer.

    Fail-closed: ``dequeue``/``peek`` on an empty queue raise ``IndexError``.
    """

    def __init__(self) -> None:
        self._data: List[Any] = []
        self._head: int = 0

    def enqueue(self, item: Any) -> None:
        self._data.append(item)

    def dequeue(self) -> Any:
        if self.is_empty():
            raise IndexError("dequeue from empty queue")
        item = self._data[self._head]
        self._head += 1
        if self._head > 64 and self._head * 2 > len(self._data):
            self._data = self._data[self._head :]
            self._head = 0
        return item

    def peek(self) -> Any:
        if self.is_empty():
            raise IndexError("peek from empty queue")
        return self._data[self._head]

    def is_empty(self) -> bool:
        return self._head >= len(self._data)

    def __len__(self) -> int:
        return len(self._data) - self._head


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
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
    q = ArrayQueue()
    assert q.is_empty() and len(q) == 0
    q.enqueue(1); q.enqueue(2); q.enqueue(3)
    assert len(q) == 3 and q.peek() == 1
    assert q.dequeue() == 1 and q.dequeue() == 2
    assert q.peek() == 3 and len(q) == 1
    assert q.dequeue() == 3 and q.is_empty()
    try:
        q.dequeue()
    except IndexError:
        pass
    else:
        raise AssertionError("dequeue on empty must raise IndexError")
    try:
        q.peek()
    except IndexError:
        pass
    else:
        raise AssertionError("peek on empty must raise IndexError")
    for i in range(200):
        q.enqueue(i)
    for i in range(200):
        assert q.dequeue() == i
    assert q.is_empty()
    assert stdlib_only()
    print("queue-01 OK: array FIFO")


if __name__ == "__main__":
    main()
