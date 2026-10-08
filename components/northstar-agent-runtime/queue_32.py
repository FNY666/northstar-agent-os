"""sort_queue: sort a queue's items via repeated minimum-selection with rotations. IS: a sorted list; works on empty and single-item inputs. IS NOT: an O(n log n) sort (this is the queue-rotation selection sort)."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-32.v1"

def sort_queue(items: List[Any]) -> List[Any]:
    """Return the items of ``items`` in ascending order using queue rotations."""
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    q: deque = deque(items)
    out: List[Any] = []
    while q:
        m = min(q)
        for _ in range(len(q)):
            if q[0] == m:
                break
            q.append(q.popleft())
        out.append(q.popleft())
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
    assert sort_queue([3, 1, 4, 1, 5]) == [1, 1, 3, 4, 5]
    assert sort_queue([]) == []
    assert sort_queue([7]) == [7]
    assert sort_queue([5, 4, 3, 2, 1]) == [1, 2, 3, 4, 5]
    src = [2, 1]
    assert sort_queue(src) == [1, 2] and src == [2, 1]
    try:
        sort_queue("321")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-32 OK: queue rotation sort")


if __name__ == "__main__":
    main()
