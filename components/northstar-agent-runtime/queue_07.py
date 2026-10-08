"""reverse_first_k: reverse the first k elements of a queue, leaving the rest in order. IS: a queue transform; k outside [0, n] raises ValueError. IS NOT: an in-place reversal of the caller's list object."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-07.v1"

def _req_list(value: object, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return list(value)


def _req_k(k: object, n: int) -> int:
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if k < 0 or k > n:
        raise ValueError("k must satisfy 0 <= k <= len(items)")
    return k


def reverse_first_k(items: List[Any], k: int) -> List[Any]:
    """Return a new list with the first ``k`` items reversed in place-order."""
    items = _req_list(items, "items")
    k = _req_k(k, len(items))
    q: deque = deque(items)
    stack: List[Any] = []
    for _ in range(k):
        stack.append(q.popleft())
    while stack:
        q.append(stack.pop())
    for _ in range(len(items) - k):
        q.append(q.popleft())
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
    assert reverse_first_k([1, 2, 3, 4, 5], 3) == [3, 2, 1, 4, 5]
    assert reverse_first_k([1, 2, 3], 0) == [1, 2, 3]
    assert reverse_first_k([1, 2, 3], 3) == [3, 2, 1]
    assert reverse_first_k([], 0) == []
    src = [1, 2]
    assert reverse_first_k(src, 1) == [1, 2] and src == [1, 2]  # k=1 is identity
    for bad_k in (-1, 4, "2", 2.0):
        try:
            reverse_first_k([1, 2, 3], bad_k)
        except ValueError:
            pass
        else:
            raise AssertionError(f"k={bad_k!r} must raise ValueError")
    try:
        reverse_first_k("abc", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("non-list items must raise ValueError")
    assert stdlib_only()
    print("queue-07 OK: reverse first k")


if __name__ == "__main__":
    main()
