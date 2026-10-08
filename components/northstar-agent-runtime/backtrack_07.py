"""Backtracking: Maze path finding.

Finds one path from the start cell 'S' to the exit cell 'E' in a maze grid
(4-directional moves; '#' walls), stopping at the first path found.

IS: a DFS backtracking search returning one valid S->E path or None.
IS NOT: a shortest-path finder (BFS/Dijkstra); NOT a multi-exit enumerator.
"""

from typing import List, Optional, Tuple
import ast

VERSION = "backtrack_07.v1"

DIRS = [(1, 0), (-1, 0), (0, 1), (0, -1)]


def find_path(maze: List[List[str]]) -> Optional[List[Tuple[int, int]]]:
    start = exit_ = None
    for r, row in enumerate(maze):
        for c, ch in enumerate(row):
            if ch == "S":
                start = (r, c)
            elif ch == "E":
                exit_ = (r, c)
    if start is None or exit_ is None:
        return None
    rows, cols = len(maze), len(maze[0])
    visited = [[False] * cols for _ in range(rows)]
    path: List[Tuple[int, int]] = []

    def dfs(r: int, c: int) -> bool:
        if (r, c) == exit_:
            path.append((r, c))
            return True
        if r < 0 or r >= rows or c < 0 or c >= cols:
            return False
        if visited[r][c] or maze[r][c] == "#":
            return False
        visited[r][c] = True
        path.append((r, c))
        for dr, dc in DIRS:
            if dfs(r + dr, c + dc):
                return True
        path.pop()
        return False

    return list(path) if dfs(*start) else None


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
        ["S", ".", "#", "."],
        ["#", ".", "#", "."],
        ["#", ".", ".", "."],
        ["#", "#", "#", "E"],
    ]
    path = find_path(maze)
    assert path is not None
    assert path[0] == (0, 0) and path[-1] == (3, 3)
    for (r1, c1), (r2, c2) in zip(path, path[1:]):
        assert abs(r1 - r2) + abs(c1 - c2) == 1
        assert maze[r2][c2] != "#"
    no_exit = [["S", "#"], ["#", "."]]
    assert find_path(no_exit) is None
    unsolvable = [["S", "#", "E"], ["#", "#", "#"]]
    assert find_path(unsolvable) is None
    assert stdlib_only()
    print("backtrack_07 OK")


if __name__ == "__main__":
    main()
