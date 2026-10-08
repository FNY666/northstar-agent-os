"""generate_binary_numbers: first n binary numbers generated level-by-level with a queue. IS: a list of n binary strings; n < 1 raises ValueError. IS NOT: a bit-manipulation generator (this is the queue BFS construction)."""

from __future__ import annotations

import ast
from collections import deque
from typing import List
VERSION = "queue-27.v1"

def generate_binary_numbers(n: int) -> List[str]:
    """Return the binary representations of ``1..n`` in order."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    q: deque = deque(["1"])
    out: List[str] = []
    for _ in range(n):
        cur = q.popleft()
        out.append(cur)
        q.append(cur + "0")
        q.append(cur + "1")
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
    assert generate_binary_numbers(1) == ["1"]
    assert generate_binary_numbers(5) == ["1", "10", "11", "100", "101"]
    assert generate_binary_numbers(8)[-1] == "1000"
    for bad in (0, -2, "5", 2.5):
        try:
            generate_binary_numbers(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"n={bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-27 OK: binary BFS generation")


if __name__ == "__main__":
    main()
