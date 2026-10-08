"""LinkedQueue: FIFO queue on a singly linked list with head/tail pointers. IS: a pointer-based FIFO queue; dequeue/peek on empty raise IndexError. IS NOT: a doubly linked list or an intrusive kernel-style queue."""

from __future__ import annotations

import ast
from typing import Any, Optional
VERSION = "queue-06.v1"

class _Node:
    __slots__ = ("item", "next")

    def __init__(self, item: Any) -> None:
        self.item = item
        self.next: Optional["_Node"] = None


class LinkedQueue:
    """Singly-linked FIFO queue."""

    def __init__(self) -> None:
        self._head: Optional[_Node] = None
        self._tail: Optional[_Node] = None
        self._size = 0

    def enqueue(self, item: Any) -> None:
        node = _Node(item)
        if self._tail is None:
            self._head = self._tail = node
        else:
            self._tail.next = node
            self._tail = node
        self._size += 1

    def dequeue(self) -> Any:
        if self._head is None:
            raise IndexError("dequeue from empty queue")
        node = self._head
        self._head = node.next
        if self._head is None:
            self._tail = None
        self._size -= 1
        return node.item

    def peek(self) -> Any:
        if self._head is None:
            raise IndexError("peek from empty queue")
        return self._head.item

    def is_empty(self) -> bool:
        return self._size == 0

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
    q = LinkedQueue()
    assert q.is_empty() and len(q) == 0
    q.enqueue(10); q.enqueue(20); q.enqueue(30)
    assert q.peek() == 10 and len(q) == 3
    assert [q.dequeue(), q.dequeue(), q.dequeue()] == [10, 20, 30]
    assert q.is_empty()
    q.enqueue(99)
    assert q.peek() == 99 and q.dequeue() == 99  # tail reset path
    assert q.is_empty()
    try:
        q.dequeue()
    except IndexError:
        pass
    else:
        raise AssertionError("dequeue on empty must raise IndexError")
    assert stdlib_only()
    print("queue-06 OK: linked-list FIFO")


if __name__ == "__main__":
    main()
