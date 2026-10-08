"""Backtracking: Rat in a maze (all paths).

Finds ALL paths for a rat from the top-left corner (0, 0) to the bottom-right
corner (n-1, n-1) of a square binary maze (1 = open, 0 = blocked), with
4-directional moves and no cell revisits.

IS: exhaustive enumeration of all valid paths as coordinate lists.
IS NOT: a shortest-path-only solver; NOT a diagonal-move variant.
"""

from typing import List, Tuple
import ast

VERSION = "backtrack_08.v1"

DIRS = [(1, 0), (-1, 0), (0, 1), (0, -1)]


def all_paths(maze: List[List[int]]) -> List[List[Tuple[int, int]]]:
    n = len(maze)
    if n == 0 or maze[0][0] == 0 or maze[n - 1][n - 1] == 0:
        return []
    paths: List[List[Tuple[int, int]]] = []
    visited = [[False] * n for _ in range(n)]
    path: List[Tuple[int, int]] = []

    def dfs(r: int, c: int) -> None:
        if r == n - 1 and c == n - 1:
            paths.append(list(path) + [(r, c)])
            return
        if r < 0 or r >= n or c < 0 or c >= n:
            return
        if visited[r][c] or maze[r][c] == 0:
            return
        visited[r][c] = True
        path.append((r, c))
        for dr, dc in DIRS:
            dfs(r + dr, c + dc)
        path.pop()
        visited[r][c] = False

    dfs(0, 0)
    return paths


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
    maze = [
        [1, 1, 0],
        [0, 1, 0],
        [1, 1, 1],
    ]
    paths = all_paths(maze)
    assert len(paths) == 1
    assert paths[0][0] == (0, 0) and paths[0][-1] == (2, 2)
    open_maze = [[1, 1], [1, 1]]
    assert len(all_paths(open_maze)) == 2
    assert all_paths([[1]]) == [[(0, 0)]]
    assert all_paths([[0, 1], [1, 1]]) == []
    assert stdlib_only()
    print("backtrack_08 OK")


if __name__ == "__main__":
    main()
