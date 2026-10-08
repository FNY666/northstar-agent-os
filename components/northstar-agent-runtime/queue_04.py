"""DequeBasic: double-ended queue with O(1) push/pop on both ends via collections.deque. IS: a double-ended queue; pops on empty raise IndexError. IS NOT: a priority queue or a thread-safe blocking deque."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any
VERSION = "queue-04.v1"

class DequeBasic:
    """Thin fail-closed wrapper around ``collections.deque``."""

    def __init__(self) -> None:
        self._d: deque = deque()

    def push_front(self, item: Any) -> None:
        self._d.appendleft(item)

    def push_back(self, item: Any) -> None:
        self._d.append(item)

    def pop_front(self) -> Any:
        if not self._d:
            raise IndexError("pop_front from empty deque")
        return self._d.popleft()

    def pop_back(self) -> Any:
        if not self._d:
            raise IndexError("pop_back from empty deque")
        return self._d.pop()

    def peek_front(self) -> Any:
        if not self._d:
            raise IndexError("peek_front from empty deque")
        return self._d[0]

    def peek_back(self) -> Any:
        if not self._d:
            raise IndexError("peek_back from empty deque")
        return self._d[-1]

    def is_empty(self) -> bool:
        return not self._d

    def __len__(self) -> int:
        return len(self._d)


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
    d = DequeBasic()
    d.push_back(1); d.push_front(0); d.push_back(2)
    assert d.peek_front() == 0 and d.peek_back() == 2 and len(d) == 3
    assert d.pop_front() == 0 and d.pop_back() == 2 and d.pop_front() == 1
    assert d.is_empty()
    try:
        d.pop_front()
    except IndexError:
        pass
    else:
        raise AssertionError("pop_front on empty must raise IndexError")
    try:
        d.pop_back()
    except IndexError:
        pass
    else:
        raise AssertionError("pop_back on empty must raise IndexError")
    assert stdlib_only()
    print("queue-04 OK: double-ended queue")


if __name__ == "__main__":
    main()
