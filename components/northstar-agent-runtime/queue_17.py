"""StackViaOneQueue: LIFO stack implemented with a single FIFO queue via rotation. IS: a stack on one queue; pop/top on empty raise IndexError. IS NOT: a queue built from stacks (the reverse construction)."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any
VERSION = "queue-17.v1"

class StackViaOneQueue:
    """Stack on one queue: ``push`` rotates the queue so the new item is front."""

    def __init__(self) -> None:
        self._q: deque = deque()

    def push(self, item: Any) -> None:
        self._q.append(item)
        for _ in range(len(self._q) - 1):
            self._q.append(self._q.popleft())

    def pop(self) -> Any:
        if not self._q:
            raise IndexError("pop from empty stack")
        return self._q.popleft()

    def top(self) -> Any:
        if not self._q:
            raise IndexError("top from empty stack")
        return self._q[0]

    def empty(self) -> bool:
        return not self._q


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
    s = StackViaOneQueue()
    s.push("a"); s.push("b"); s.push("c")
    assert s.top() == "c"
    assert [s.pop(), s.pop(), s.pop()] == ["c", "b", "a"]
    assert s.empty()
    s.push(1)
    assert s.top() == 1 and s.pop() == 1 and s.empty()
    try:
        s.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("pop on empty must raise IndexError")
    assert stdlib_only()
    print("queue-17 OK: stack from one queue")


if __name__ == "__main__":
    main()
