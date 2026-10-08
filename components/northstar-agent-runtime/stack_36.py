"""Implement Stack using Two Queues. IS: a LIFO stack where push rotates the active queue. IS NOT: a list-backed stack."""

from __future__ import annotations

import ast

VERSION = "stack-36.v1"

def _req_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int")
    return value


class MyStack:
    """LIFO stack built from two FIFO queues (lists used as queues)."""

    def __init__(self) -> None:
        self._q1: list[int] = []
        self._q2: list[int] = []

    def push(self, x: int) -> None:
        x = _req_int(x, "x")
        self._q2.append(x)
        while self._q1:
            self._q2.append(self._q1.pop(0))
        self._q1, self._q2 = self._q2, self._q1

    def pop(self) -> int:
        if not self._q1:
            raise ValueError("pop from empty stack")
        return self._q1.pop(0)

    def top(self) -> int:
        if not self._q1:
            raise ValueError("top of empty stack")
        return self._q1[0]

    def empty(self) -> bool:
        return not self._q1

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
    st = MyStack()
    st.push(1)
    st.push(2)
    assert st.top() == 2
    assert st.pop() == 2
    assert st.empty() is False
    assert st.pop() == 1
    assert st.empty() is True
    try:
        st.pop()
    except ValueError:
        pass
    else:
        raise AssertionError("pop from empty must raise ValueError")
    assert stdlib_only()
    print("stack_36 OK")


if __name__ == "__main__":
    main()
