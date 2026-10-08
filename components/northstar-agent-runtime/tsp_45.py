"""Tour repair (fix invalid tour with duplicates/missing cities) (TSP-045), Simulated."""
from __future__ import annotations
import ast

VERSION = "tsp-tour-repair.v1"

def repair(tour: list[int], n: int) -> list[int]:
    """Return a valid permutation of range(n): drop dups/out-of-range, append missing."""
    seen: set[int] = set()
    fixed: list[int] = []
    for c in tour:
        if 0 <= c < n and c not in seen:
            seen.add(c)
            fixed.append(c)
    for c in range(n):
        if c not in seen:
            fixed.append(c)
    return fixed

def is_valid(tour: list[int], n: int) -> bool:
    return sorted(tour) == list(range(n))

def main() -> None:
    r = repair([0, 1, 1, 2, 9, -3], 4)
    assert is_valid(r, 4), r
    assert r[:3] == [0, 1, 2]
    assert repair([], 0) == []
    assert repair([5, 5, 5], 3) == [0, 1, 2]
    assert is_valid(repair([2, 0], 3), 3)
    assert stdlib_only()
    print('tsp-tour-repair.v1 OK')

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True

if __name__ == "__main__":
    main()
