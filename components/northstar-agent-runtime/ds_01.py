"""DS: Dynamic Array (01/50). resizable array"""
from __future__ import annotations

import ast

#: Module version.
DS_01_VERSION = "ds-01-array.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-01.array.v1"


class DynamicArray:
    """Resizable array backed by a Python list."""

    def __init__(self):
        self._data = []

    def append(self, value):
        self._data.append(value)

    def get(self, index):
        if not 0 <= index < len(self._data):
            raise IndexError("index out of range")
        return self._data[index]

    def set(self, index, value):
        if not 0 <= index < len(self._data):
            raise IndexError("index out of range")
        self._data[index] = value

    def insert(self, index, value):
        self._data.insert(index, value)

    def remove(self, index):
        if not 0 <= index < len(self._data):
            raise IndexError("index out of range")
        return self._data.pop(index)

    def __len__(self):
        return len(self._data)

    def to_list(self):
        return list(self._data)

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
    a = DynamicArray()
    a.append(1); a.append(2); a.append(3)
    assert a.get(1) == 2
    a.set(1, 20)
    assert a.get(1) == 20
    a.insert(0, 0)
    assert a.to_list() == [0, 1, 20, 3]
    assert a.remove(0) == 0
    assert len(a) == 3
    assert stdlib_only()
    print("ds-01 OK: append/get/set/insert/remove")


if __name__ == "__main__":
    main()
