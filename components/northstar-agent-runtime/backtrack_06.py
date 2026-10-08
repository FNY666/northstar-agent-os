"""Backtracking: Word search in a grid.

Finds a path through a letter grid (4-directional moves, no cell reuse)
that spells the target word, using DFS backtracking from every start cell.

IS: returns one (r, c) path spelling the word, or None if absent.
IS NOT: a Boggle/multi-word solver; NOT a shortest-path or A* implementation.
"""

from typing import List, Optional, Tuple
import ast

VERSION = "backtrack_06.v1"

DIRS = [(1, 0), (-1, 0), (0, 1), (0, -1)]


def find_word(grid: List[List[str]], word: str) -> Optional[List[Tuple[int, int]]]:
    if not word or not grid:
        return None
    rows, cols = len(grid), len(grid[0])
    visited = [[False] * cols for _ in range(rows)]

    def dfs(r: int, c: int, i: int, path: List[Tuple[int, int]]) -> Optional[List[Tuple[int, int]]]:
        if i == len(word):
            return list(path)
        if r < 0 or r >= rows or c < 0 or c >= cols:
            return None
        if visited[r][c] or grid[r][c] != word[i]:
            return None
        visited[r][c] = True
        path.append((r, c))
        for dr, dc in DIRS:
            found = dfs(r + dr, c + dc, i + 1, path)
            if found is not None:
                return found
        path.pop()
        visited[r][c] = False
        return None

    for r in range(rows):
        for c in range(cols):
            found = dfs(r, c, 0, [])
            if found is not None:
                return found
    return None


def stdlib_only() -> bool:
    allowed = {"typing", "ast"}
    with open(__file__) as f:
        tree = ast.parse(f.read())
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
    grid = [
        ["A", "B", "C", "E"],
        ["S", "F", "C", "S"],
        ["A", "D", "E", "E"],
    ]
    path = find_word(grid, "ABCCED")
    assert path is not None
    assert "".join(grid[r][c] for r, c in path) == "ABCCED"
    assert len(path) == 6 and len(set(path)) == 6
    assert find_word(grid, "ABCB") is None
    assert find_word(grid, "A") == [(0, 0)] or find_word(grid, "A") == [(2, 0)]
    assert stdlib_only()
    print("backtrack_06 OK")


if __name__ == "__main__":
    main()
