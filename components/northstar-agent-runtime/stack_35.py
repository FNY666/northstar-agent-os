"""Implement Queue using Two Stacks. IS: an amortised queue with an inbox stack and an outbox stack. IS NOT: a collections.deque wrapper."""

from __future__ import annotations

import ast

VERSION = "stack-35.v1"

def _req_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int")
    return value


class MyQueue:
    """FIFO queue built from two LIFO stacks."""

    def __init__(self) -> None:
        self._in: list[int] = []
        self._out: list[int] = []

    def push(self, x: int) -> None:
        self._in.append(_req_int(x, "x"))

    def _fill(self) -> None:
        if not self._out:
            while self._in:
                self._out.append(self._in.pop())

    def pop(self) -> int:
        self._fill()
        if not self._out:
            raise ValueError("pop from empty queue")
        return self._out.pop()

    def peek(self) -> int:
        self._fill()
        if not self._out:
            raise ValueError("peek of empty queue")
        return self._out[-1]

    def empty(self) -> bool:
        return not self._in and not self._out

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    q = MyQueue()
    q.push(1)
    q.push(2)
    assert q.peek() == 1
    assert q.pop() == 1
    assert q.empty() is False
    assert q.pop() == 2
    assert q.empty() is True
    try:
        q.pop()
    except ValueError:
        pass
    else:
        raise AssertionError("pop from empty must raise ValueError")
    try:
        q.push("x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-int push must raise ValueError")
    assert stdlib_only()
    print("stack_35 OK")


if __name__ == "__main__":
    main()
