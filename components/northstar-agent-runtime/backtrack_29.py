"""Backtracking: count Android unlock patterns on the 3x3 grid.

IS: counts distinct unlock patterns whose length is in [m, n] on keys
1-9, enforcing the "knight-move" rule that a jump over an unvisited
intermediate key is forbidden. IS NOT: a security analysis - it counts
patterns combinatorially and says nothing about real-world guessability,
shoulder-surfing, or smudge attacks.
"""

import ast
from typing import Dict, Optional, Tuple

VERSION = "backtrack_29.v1"

_JUMPS: Dict[Tuple[int, int], int] = {
    (1, 3): 2, (3, 1): 2,
    (1, 7): 4, (7, 1): 4,
    (3, 9): 6, (9, 3): 6,
    (7, 9): 8, (9, 7): 8,
    (1, 9): 5, (9, 1): 5,
    (3, 7): 5, (7, 3): 5,
    (2, 8): 5, (8, 2): 5,
    (4, 6): 5, (6, 4): 5,
}


def count_patterns(m: int, n: int) -> int:
    """Number of valid patterns with m <= length <= n."""
    total = 0
    visited = [False] * 10

    def dfs(cur: int, length: int) -> None:
        nonlocal total
        if m <= length <= n:
            total += 1
        if length == n:
            return
        for nxt in range(1, 10):
            if visited[nxt]:
                continue
            jump = _JUMPS.get((cur, nxt))
            if jump is not None and not visited[jump]:
                continue
            visited[nxt] = True
            dfs(nxt, length + 1)
            visited[nxt] = False

    for start in range(1, 10):
        visited[start] = True
        dfs(start, 1)
        visited[start] = False
    return total


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert count_patterns(1, 1) == 9
    assert count_patterns(2, 2) == 56
    assert count_patterns(1, 2) == 65
    assert count_patterns(1, 3) == 385
    print("backtrack_29 OK")


if __name__ == "__main__":
    main()
