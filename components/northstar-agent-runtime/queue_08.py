"""interleave_halves: interleave the two halves of an even-length queue: [1,2,3,4] -> [1,3,2,4]. IS: a queue interleave; odd-length input raises ValueError. IS NOT: a shuffle that works on odd lengths or mutates the input."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, List
VERSION = "queue-08.v1"

def interleave_halves(items: List[Any]) -> List[Any]:
    """Return ``[a1, b1, a2, b2, ...]`` from ``[a1..an, b1..bn]``."""
    if not isinstance(items, list):
        raise ValueError("items must be a list")
    if len(items) % 2 != 0:
        raise ValueError("items must have even length")
    q: deque = deque(items)
    half = len(items) // 2
    first = [q.popleft() for _ in range(half)]
    out: List[Any] = []
    for a in first:
        out.append(a)
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
    assert interleave_halves([1, 2, 3, 4, 5, 6]) == [1, 4, 2, 5, 3, 6]
    assert interleave_halves([1, 2]) == [1, 2]
    assert interleave_halves([]) == []
    try:
        interleave_halves([1, 2, 3])
    except ValueError:
        pass
    else:
        raise AssertionError("odd length must raise ValueError")
    try:
        interleave_halves((1, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("non-list must raise ValueError")
    assert stdlib_only()
    print("queue-08 OK: interleave halves")


if __name__ == "__main__":
    main()
