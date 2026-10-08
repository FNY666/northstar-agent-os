"""Last day you can still cross, solved in reverse.

Start from the all-land grid, then add water cells back in reverse day
order, unioning with land neighbours. The first day top connects to
bottom going backwards is the answer minus one... actually the last
crossable day is the reversed day at which connection first appears.
"""
import ast
import sys
from typing import List, Tuple

UF_28_VERSION = "uf-28.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)


def last_cross_day(rows: int, cols: int,
                   cells: List[Tuple[int, int]]) -> int:
    """Last day (1-indexed) a top-to-bottom path still exists."""
    uf = UnionFind(rows * cols + 2)
    top, bottom = rows * cols, rows * cols + 1
    land = [[False] * cols for _ in range(rows)]

    def idx(r: int, c: int) -> int:
        return r * cols + c

    for day in range(len(cells) - 1, -1, -1):
        r, c = cells[day][0] - 1, cells[day][1] - 1
        land[r][c] = True
        i = idx(r, c)
        if r == 0:
            uf.union(i, top)
        if r == rows - 1:
            uf.union(i, bottom)
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and land[nr][nc]:
                uf.union(i, idx(nr, nc))
        if uf.connected(top, bottom):
            return day
    return 0

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True

def main() -> None:
    assert last_cross_day(2, 2, [(1, 1), (2, 1), (1, 2), (2, 2)]) == 2
    assert last_cross_day(3, 3, [(1, 2), (2, 1), (3, 3), (2, 3), (1, 1),
                                (1, 3), (2, 2), (3, 1), (3, 2)]) == 3
    assert last_cross_day(1, 1, [(1, 1)]) == 0
    assert stdlib_only()
    print("uf-28 OK")


if __name__ == "__main__":
    main()
