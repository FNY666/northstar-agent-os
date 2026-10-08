"""Backtracking: simplified Fillomino-style region fill.

IS: given seed cells each labeled with a region size, fills the whole
grid with region ids so that every seed's 4-connected region has exactly
its labeled size and the regions partition the grid (mock-simplified
backtracking over cell->region assignment with a connectivity check).
IS NOT: real Fillomino - the "no two same-size regions may touch"
rule is deliberately omitted, and polyomino shapes are unrestricted.
"""

import ast
from typing import Dict, List, Optional, Tuple

VERSION = "backtrack_30.v1"

_NEIGHBORS = ((1, 0), (-1, 0), (0, 1), (0, -1))


def fill_regions(
    rows: int, cols: int, seeds: Dict[Tuple[int, int], int]
) -> Optional[List[List[int]]]:
    """Fill the grid with region ids (seed indices). None if impossible."""
    seed_list = list(seeds.items())
    k = len(seed_list)
    if k == 0 or sum(size for _, size in seed_list) != rows * cols:
        return None
    board = [[-1] * cols for _ in range(rows)]
    counts = [0] * k
    for idx, ((r, c), _size) in enumerate(seed_list):
        board[r][c] = idx
        counts[idx] = 1
    cells = [(r, c) for r in range(rows) for c in range(cols)
             if board[r][c] == -1]

    def regions_ok() -> bool:
        for idx, ((sr, sc), size) in enumerate(seed_list):
            seen = {(sr, sc)}
            stack = [(sr, sc)]
            while stack:
                r, c = stack.pop()
                for dr, dc in _NEIGHBORS:
                    nr, nc = r + dr, c + dc
                    if (0 <= nr < rows and 0 <= nc < cols
                            and board[nr][nc] == idx
                            and (nr, nc) not in seen):
                        seen.add((nr, nc))
                        stack.append((nr, nc))
            if len(seen) != size:
                return False
        return True

    def dfs(i: int) -> bool:
        if i == len(cells):
            return regions_ok()
        r, c = cells[i]
        for idx in range(k):
            size = seed_list[idx][1]
            if counts[idx] >= size:
                continue
            board[r][c] = idx
            counts[idx] += 1
            if dfs(i + 1):
                return True
            counts[idx] -= 1
            board[r][c] = -1
        return False

    if dfs(0):
        return [row[:] for row in board]
    return None


def _valid_fill(rows: int, cols: int, seeds: Dict[Tuple[int, int], int],
                board: List[List[int]]) -> bool:
    from collections import deque  # local import keeps top-level stdlib-only
    seed_list = list(seeds.items())
    for idx, ((sr, sc), size) in enumerate(seed_list):
        if board[sr][sc] != idx:
            return False
        seen = {(sr, sc)}
        queue = deque([(sr, sc)])
        while queue:
            r, c = queue.popleft()
            for dr, dc in _NEIGHBORS:
                nr, nc = r + dr, c + dc
                if (0 <= nr < rows and 0 <= nc < cols
                        and board[nr][nc] == idx and (nr, nc) not in seen):
                    seen.add((nr, nc))
                    queue.append((nr, nc))
        if len(seen) != size:
            return False
    return all(board[r][c] != -1 for r in range(rows) for c in range(cols))


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast", "collections"}
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
    got = fill_regions(2, 2, {(0, 0): 2, (1, 1): 2})
    assert got is not None
    assert _valid_fill(2, 2, {(0, 0): 2, (1, 1): 2}, got)
    # Sizes summing past the grid area -> impossible.
    assert fill_regions(2, 2, {(0, 0): 3, (1, 1): 3}) is None
    # Single cell trivially solved.
    assert fill_regions(1, 1, {(0, 0): 1}) == [[0]]
    # 2x3 with an L-shaped region of 3 and a domino of 3.
    got2 = fill_regions(2, 3, {(0, 0): 3, (1, 2): 3})
    assert got2 is not None
    assert _valid_fill(2, 3, {(0, 0): 3, (1, 2): 3}, got2)
    print("backtrack_30 OK")


if __name__ == "__main__":
    main()
