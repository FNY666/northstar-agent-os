"""merge_sorted_queues: merge two sorted queues into one sorted list, stable on ties. IS: a merged sorted list; non-list inputs raise ValueError. IS NOT: a heap-based k-way merge (this is the two-queue merge)."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-35.v1"

def merge_sorted_queues(a: List[Any], b: List[Any]) -> List[Any]:
    """Merge two ascending-sorted lists into one ascending list."""
    if not isinstance(a, list) or not isinstance(b, list):
        raise ValueError("a and b must be lists")
    qa: deque = deque(a)
    qb: deque = deque(b)
    out: List[Any] = []
    while qa and qb:
        if qa[0] <= qb[0]:
            out.append(qa.popleft())
        else:
            out.append(qb.popleft())
    out.extend(qa)
    out.extend(qb)
    return out


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
    assert merge_sorted_queues([1, 3, 5], [2, 4, 6]) == [1, 2, 3, 4, 5, 6]
    assert merge_sorted_queues([], [1, 2]) == [1, 2]
    assert merge_sorted_queues([1, 2], []) == [1, 2]
    assert merge_sorted_queues([], []) == []
    assert merge_sorted_queues([1, 2, 2], [2, 3]) == [1, 2, 2, 2, 3]
    try:
        merge_sorted_queues([1], "23")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-35 OK: two-queue merge")


if __name__ == "__main__":
    main()
