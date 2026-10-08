"""josephus: Josephus survivor (1-indexed) for n people eliminating every k-th via queue. IS: a survivor index in 1..n; n < 1 or k < 1 raises ValueError. IS NOT: a closed-form O(n) recurrence (this is the queue simulation)."""

from __future__ import annotations

import ast
from collections import deque
VERSION = "queue-25.v1"

def josephus(n: int, k: int) -> int:
    """Return the 1-indexed survivor of the Josephus problem."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1:
        raise ValueError("k must be a positive int")
    q: deque = deque(range(1, n + 1))
    while len(q) > 1:
        q.rotate(-(k - 1))
        q.popleft()
    return q[0]


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
    assert josephus(7, 3) == 4
    assert josephus(1, 5) == 1
    assert josephus(5, 2) == 3
    assert josephus(6, 6) == 4
    assert josephus(10, 1) == 10
    for bad in ((0, 3), (5, 0), (-1, 2), ("7", 3)):
        try:
            josephus(*bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"args {bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-25 OK: Josephus survivor")


if __name__ == "__main__":
    main()
