"""CircularQueue: fixed-capacity ring-buffer FIFO queue with wrap-around indices. IS: a bounded FIFO; enqueue on full raises OverflowError, dequeue on empty raises IndexError. IS NOT: a resizable or unbounded queue."""

from __future__ import annotations

import ast
from typing import Any, List
VERSION = "queue-03.v1"

class CircularQueue:
    """Ring buffer queue of fixed ``capacity``."""

    def __init__(self, capacity: int) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("capacity must be a positive int")
        self._cap = capacity
        self._buf: List[Any] = [None] * capacity
        self._head = 0
        self._size = 0

    def enqueue(self, item: Any) -> None:
        if self.is_full():
            raise OverflowError("enqueue on full queue")
        self._buf[(self._head + self._size) % self._cap] = item
        self._size += 1

    def dequeue(self) -> Any:
        if self.is_empty():
            raise IndexError("dequeue from empty queue")
        item = self._buf[self._head]
        self._buf[self._head] = None
        self._head = (self._head + 1) % self._cap
        self._size -= 1
        return item

    def peek(self) -> Any:
        if self.is_empty():
            raise IndexError("peek from empty queue")
        return self._buf[self._head]

    def is_empty(self) -> bool:
        return self._size == 0

    def is_full(self) -> bool:
        return self._size == self._cap

    def __len__(self) -> int:
        return self._size


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
    q = CircularQueue(3)
    q.enqueue(1); q.enqueue(2); q.enqueue(3)
    assert q.is_full()
    try:
        q.enqueue(4)
    except OverflowError:
        pass
    else:
        raise AssertionError("enqueue on full must raise OverflowError")
    assert q.dequeue() == 1
    q.enqueue(4)  # wrap-around slot
    assert q.dequeue() == 2 and q.dequeue() == 3 and q.dequeue() == 4
    assert q.is_empty()
    try:
        q.dequeue()
    except IndexError:
        pass
    else:
        raise AssertionError("dequeue on empty must raise IndexError")
    for bad in (0, -1, "3", 2.5, True):
        try:
            CircularQueue(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"capacity {bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-03 OK: ring buffer")


if __name__ == "__main__":
    main()
