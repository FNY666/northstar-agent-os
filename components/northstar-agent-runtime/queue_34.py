"""queue_middle: middle element of a queue via slow/fast pointers (first middle if even). IS: the middle item; empty input raises ValueError. IS NOT: the average of two middles or an index-based shortcut."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-34.v1"

def queue_middle(items: List[Any]) -> Any:
    """Return the middle item; for even length, the first of the two middles."""
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list")
    slow: deque = deque(items)
    fast: deque = deque(items)
    while len(fast) > 2:
        slow.popleft()
        fast.popleft()
        fast.popleft()
    return slow[0]


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
    assert queue_middle([1, 2, 3, 4, 5]) == 3
    assert queue_middle([1, 2, 3, 4]) == 2
    assert queue_middle([9]) == 9
    assert queue_middle(["a", "b"]) == "a"
    try:
        queue_middle([])
    except ValueError:
        pass
    else:
        raise AssertionError("empty list must raise ValueError")
    try:
        queue_middle("abc")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-34 OK: slow/fast middle")


if __name__ == "__main__":
    main()
