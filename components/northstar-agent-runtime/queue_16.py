"""StackViaQueues: LIFO stack implemented on top of two FIFO queues. IS: a stack with push/pop/top/empty; pop/top on empty raise IndexError. IS NOT: a stack with O(1) worst-case pop or a min-tracking stack."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any
VERSION = "queue-16.v1"

class StackViaQueues:
    """Stack where ``push`` is O(n) and ``pop``/``top`` are O(1)."""

    def __init__(self) -> None:
        self._q1: deque = deque()
        self._q2: deque = deque()

    def push(self, item: Any) -> None:
        self._q2.append(item)
        while self._q1:
            self._q2.append(self._q1.popleft())
        self._q1, self._q2 = self._q2, self._q1

    def pop(self) -> Any:
        if not self._q1:
            raise IndexError("pop from empty stack")
        return self._q1.popleft()

    def top(self) -> Any:
        if not self._q1:
            raise IndexError("top from empty stack")
        return self._q1[0]

    def empty(self) -> bool:
        return not self._q1


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
    s = StackViaQueues()
    assert s.empty()
    s.push(1); s.push(2); s.push(3)
    assert s.top() == 3 and not s.empty()
    assert s.pop() == 3 and s.pop() == 2
    s.push(4)
    assert s.pop() == 4 and s.pop() == 1 and s.empty()
    try:
        s.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("pop on empty must raise IndexError")
    try:
        s.top()
    except IndexError:
        pass
    else:
        raise AssertionError("top on empty must raise IndexError")
    assert stdlib_only()
    print("queue-16 OK: stack from two queues")


if __name__ == "__main__":
    main()
