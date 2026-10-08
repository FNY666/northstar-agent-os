"""TwoStackQueue: FIFO queue built from two LIFO lists with amortized O(1) operations. IS: a queue whose dequeue cost is amortized O(1) via lazy transfer. IS NOT: a queue with worst-case O(1) dequeue or lock-free concurrency."""

from __future__ import annotations

import ast
from typing import Any, List
VERSION = "queue-02.v1"

class TwoStackQueue:
    """Queue from two stacks: ``_in`` for enqueue, ``_out`` for dequeue."""

    def __init__(self) -> None:
        self._in: List[Any] = []
        self._out: List[Any] = []

    def enqueue(self, item: Any) -> None:
        self._in.append(item)

    def _shift(self) -> None:
        if not self._out:
            while self._in:
                self._out.append(self._in.pop())

    def dequeue(self) -> Any:
        self._shift()
        if not self._out:
            raise IndexError("dequeue from empty queue")
        return self._out.pop()

    def peek(self) -> Any:
        self._shift()
        if not self._out:
            raise IndexError("peek from empty queue")
        return self._out[-1]

    def is_empty(self) -> bool:
        return not self._in and not self._out

    def __len__(self) -> int:
        return len(self._in) + len(self._out)


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
    q = TwoStackQueue()
    assert q.is_empty()
    q.enqueue("a"); q.enqueue("b")
    assert q.dequeue() == "a"
    q.enqueue("c")
    assert q.peek() == "b" and len(q) == 2
    assert q.dequeue() == "b" and q.dequeue() == "c"
    assert q.is_empty()
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
    assert stdlib_only()
    print("queue-02 OK: two-stack FIFO")


if __name__ == "__main__":
    main()
