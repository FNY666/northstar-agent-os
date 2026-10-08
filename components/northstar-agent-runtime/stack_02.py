"""Min Stack: push/pop/top plus O(1) get_min. IS: a stack that tracks the running minimum alongside every push. IS NOT: a sorted container or a heap; pop order is still LIFO."""

from __future__ import annotations

import ast

VERSION = "stack-02.v1"

def _req_num(value: object, name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    return value


class MinStack:
    """LIFO stack with O(1) minimum retrieval."""

    def __init__(self) -> None:
        self._data: list[int | float] = []
        self._mins: list[int | float] = []

    def push(self, val: int | float) -> None:
        val = _req_num(val, "val")
        self._data.append(val)
        self._mins.append(val if not self._mins else min(val, self._mins[-1]))

    def pop(self) -> int | float:
        if not self._data:
            raise ValueError("pop from empty stack")
        self._mins.pop()
        return self._data.pop()

    def top(self) -> int | float:
        if not self._data:
            raise ValueError("top of empty stack")
        return self._data[-1]

    def get_min(self) -> int | float:
        if not self._mins:
            raise ValueError("get_min of empty stack")
        return self._mins[-1]

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
    st = MinStack()
    st.push(-2)
    st.push(0)
    st.push(-3)
    assert st.get_min() == -3
    assert st.pop() == -3
    assert st.top() == 0
    assert st.get_min() == -2
    try:
        MinStack().pop()
    except ValueError:
        pass
    else:
        raise AssertionError("pop from empty must raise ValueError")
    try:
        st.push("x")
    except ValueError:
        pass
    else:
        raise AssertionError("non-number push must raise ValueError")
    assert stdlib_only()
    print("stack_02 OK")


if __name__ == "__main__":
    main()
