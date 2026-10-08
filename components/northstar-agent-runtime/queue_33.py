"""reverse_queue_recursive: reverse a queue recursively: dequeue, recurse, enqueue on unwind. IS: a new reversed list; non-list input raises ValueError. IS NOT: an in-place recursive reversal of the caller's list."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-33.v1"

def reverse_queue_recursive(items: List[Any]) -> List[Any]:
    """Return ``items`` reversed, computed via queue recursion."""
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    q: deque = deque(items)

    def rec() -> None:
        if not q:
            return
        head = q.popleft()
        rec()
        q.append(head)

    rec()
    return list(q)


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
    assert reverse_queue_recursive([1, 2, 3]) == [3, 2, 1]
    assert reverse_queue_recursive([]) == []
    assert reverse_queue_recursive(["a"]) == ["a"]
    src = [1, 2, 3]
    assert reverse_queue_recursive(src) == [3, 2, 1] and src == [1, 2, 3]
    try:
        reverse_queue_recursive((1, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-33 OK: recursive reversal")


if __name__ == "__main__":
    main()
