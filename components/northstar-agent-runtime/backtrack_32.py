"""Backtracking: Boggle word finder (mock).

IS: finds every dictionary word (length >= min_len) formable on a letter
    grid with 8-direction adjacency and no cell reuse, using DFS with
    prefix pruning. Meant for tiny grids and dictionaries.
IS NOT: a scored Boggle game, a trie-based large-board solver, or a
    dictionary validator.
"""

from __future__ import annotations

import ast
from typing import List, Set

VERSION = "backtrack_32.v1"

_DIRECTIONS = [(-1, -1), (-1, 0), (-1, 1),
               (0, -1),           (0, 1),
               (1, -1),  (1, 0),  (1, 1)]


def _prefixes(words: Set[str]) -> Set[str]:
    prefs: Set[str] = set()
    for w in words:
        for i in range(1, len(w)):
            prefs.add(w[:i])
    return prefs


def find_words(grid: List[str], words: Set[str], min_len: int = 3) -> List[str]:
    """Return sorted list of words from ``words`` found on ``grid``."""
    if not grid or not words:
        return []
    rows, cols = len(grid), len(grid[0])
    if any(len(row) != cols for row in grid):
        raise ValueError("grid rows must all have the same length")
    prefs = _prefixes(words)
    found: Set[str] = set()
    used = [[False] * cols for _ in range(rows)]

    def dfs(r: int, c: int, cur: str) -> None:
        if cur in words and len(cur) >= min_len:
            found.add(cur)
        if cur not in prefs:
            return
        for dr, dc in _DIRECTIONS:
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and not used[nr][nc]:
                used[nr][nc] = True
                dfs(nr, nc, cur + grid[nr][nc])
                used[nr][nc] = False

    for r in range(rows):
        for c in range(cols):
            used[r][c] = True
            dfs(r, c, grid[r][c])
            used[r][c] = False
    return sorted(found)


def stdlib_only() -> bool:
    """Parse this file with ast; True only if every import is allowed."""
    allowed = {"__future__", "ast", "typing"}
    with open(__file__) as fh:
        tree = ast.parse(fh.read())
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
    grid = ["AB", "CD"]
    words = {"AB", "ABC", "ABCD", "AC", "AD", "BA", "ABA", "Z"}
    found = find_words(grid, words)
    assert found == ["ABC", "ABCD"], found
    # length-2 words excluded by min_len=3; "ABA" needs cell reuse; "Z" absent
    assert "AB" not in found and "AC" not in found and "ABA" not in found
    assert find_words(grid, words, min_len=2) == ["AB", "ABC", "ABCD", "AC", "AD", "BA"]
    # diagonal + longer path
    grid2 = ["CAT", "RER", "SON"]
    found2 = find_words(grid2, {"CAT", "TER", "SONS", "RAT", "CART"})
    assert "CAT" in found2 and "TER" in found2
    assert "SONS" not in found2  # no second S reachable
    assert "CART" in found2  # C(0,0)-A(0,1)-R(1,2)-T(0,2) is a valid walk
    assert "CARTS" not in found2  # no S adjacent to the final T
    # empty inputs / ragged grid
    assert find_words([], {"A"}) == []
    assert find_words(["AB"], set()) == []
    try:
        find_words(["AB", "C"], {"A"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for ragged grid")
    assert stdlib_only()
    print("backtrack_32 OK")


if __name__ == "__main__":
    main()
