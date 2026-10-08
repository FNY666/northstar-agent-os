"""min_perfect_squares: fewest perfect squares summing to n, found by BFS over remainders. IS: a minimum count; n < 1 raises ValueError. IS NOT: a dynamic-programming solution (this is the BFS version)."""

from __future__ import annotations

import ast
from collections import deque
VERSION = "queue-46.v1"

def min_perfect_squares(n: int) -> int:
    """Return the least number of perfect squares that sum to ``n``."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("n must be a positive int")
    squares = [i * i for i in range(1, int(n ** 0.5) + 1)]
    q: deque = deque([(n, 0)])
    seen = {n}
    while q:
        rem, steps = q.popleft()
        for s in squares:
            nxt = rem - s
            if nxt == 0:
                return steps + 1
            if nxt < 0:
                break
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, steps + 1))
    return n  # unreachable in practice; n ones always work


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
    assert min_perfect_squares(1) == 1
    assert min_perfect_squares(12) == 3
    assert min_perfect_squares(13) == 2
    assert min_perfect_squares(16) == 1
    assert min_perfect_squares(7) == 4
    for bad in (0, -4, "12", 2.5, True):
        try:
            min_perfect_squares(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"n={bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-46 OK: BFS perfect squares")


if __name__ == "__main__":
    main()
