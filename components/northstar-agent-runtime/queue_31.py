"""stable_partition_parity: stable partition of a queue: odd-position values first, then even-position values. IS: a reordered list preserving relative order; non-list input raises ValueError. IS NOT: an in-place partition or a value-parity split."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-31.v1"

def stable_partition_parity(items: List[Any]) -> List[Any]:
    """Return items at even indices followed by items at odd indices (0-based)."""
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    q: deque = deque(items)
    evens: List[Any] = []
    odds: List[Any] = []
    idx = 0
    while q:
        (evens if idx % 2 == 0 else odds).append(q.popleft())
        idx += 1
    return evens + odds


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
    assert stable_partition_parity([1, 2, 3, 4, 5, 6]) == [1, 3, 5, 2, 4, 6]
    assert stable_partition_parity([1, 2, 3]) == [1, 3, 2]
    assert stable_partition_parity([]) == []
    assert stable_partition_parity(["a"]) == ["a"]
    try:
        stable_partition_parity("abcd")
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-31 OK: stable parity partition")


if __name__ == "__main__":
    main()
