"""DS: Stack (05/50). LIFO stack"""
from __future__ import annotations

import ast

#: Module version.
DS_05_VERSION = "ds-05-stack.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-05.stack.v1"


class Stack:
    """LIFO stack."""

    def __init__(self):
        self._data = []

    def push(self, value):
        self._data.append(value)

    def pop(self):
        if not self._data:
            raise IndexError("empty")
        return self._data.pop()

    def peek(self):
        if not self._data:
            raise IndexError("empty")
        return self._data[-1]

    def is_empty(self):
        return not self._data

    def __len__(self):
        return len(self._data)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    s = Stack()
    assert s.is_empty()
    s.push(1); s.push(2)
    assert s.peek() == 2
    assert s.pop() == 2
    assert s.pop() == 1
    assert s.is_empty()
    assert stdlib_only()
    print("ds-05 OK: LIFO push/pop/peek")


if __name__ == "__main__":
    main()
