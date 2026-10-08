"""DS: Deque (07/50). double-ended queue"""
from __future__ import annotations

import ast
import collections

#: Module version.
DS_07_VERSION = "ds-07-deque.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-07.deque.v1"


class Deque:
    """Double-ended queue backed by collections.deque."""

    def __init__(self):
        self._data = collections.deque()

    def push_front(self, value):
        self._data.appendleft(value)

    def push_back(self, value):
        self._data.append(value)

    def pop_front(self):
        if not self._data:
            raise IndexError("empty")
        return self._data.popleft()

    def pop_back(self):
        if not self._data:
            raise IndexError("empty")
        return self._data.pop()

    def peek_front(self):
        if not self._data:
            raise IndexError("empty")
        return self._data[0]

    def peek_back(self):
        if not self._data:
            raise IndexError("empty")
        return self._data[-1]

    def __len__(self):
        return len(self._data)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "collections"}
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
    d = Deque()
    d.push_back(2); d.push_front(1); d.push_back(3)
    assert d.peek_front() == 1
    assert d.peek_back() == 3
    assert d.pop_front() == 1
    assert d.pop_back() == 3
    assert len(d) == 1
    assert stdlib_only()
    print("ds-07 OK: push/pop/peek both ends")


if __name__ == "__main__":
    main()
