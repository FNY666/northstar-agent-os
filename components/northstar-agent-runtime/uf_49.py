"""Number of closed islands.

Water cells (0) touching the border drain to a virtual outside node.
Every remaining water component is a closed island.
"""
import ast
import sys
from typing import List

UF_49_VERSION = "uf-49.v1"

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


def closed_islands(grid: List[List[int]]) -> int:
    """Count 0-regions fully surrounded by 1s."""
    rows, cols = len(grid), len(grid[0])
    uf = UnionFind(rows * cols + 1)
    sea = rows * cols

    def idx(r: int, c: int) -> int:
        return r * cols + c

    for r in range(rows):
        for c in range(cols):
            if grid[r][c] != 0:
                continue
            if r == 0 or r == rows - 1 or c == 0 or c == cols - 1:
                uf.union(idx(r, c), sea)
            if r > 0 and grid[r - 1][c] == 0:
                uf.union(idx(r, c), idx(r - 1, c))
            if c > 0 and grid[r][c - 1] == 0:
                uf.union(idx(r, c), idx(r, c - 1))
    seen = set()
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 0 and not uf.connected(idx(r, c), sea):
                seen.add(uf.find(idx(r, c)))
    return len(seen)

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
    g = [[1, 1, 1, 1, 1, 1, 1, 0], [1, 0, 0, 0, 0, 1, 1, 0],
         [1, 0, 1, 0, 1, 1, 1, 0], [1, 0, 0, 0, 0, 1, 0, 1],
         [1, 1, 1, 1, 1, 1, 1, 0]]
    assert closed_islands(g) == 2
    assert closed_islands([[0, 0, 1, 0, 0], [0, 1, 0, 1, 0],
                           [0, 1, 1, 1, 0]]) == 1
    assert closed_islands([[1, 1], [1, 1]]) == 0
    assert stdlib_only()
    print("uf-49 OK")


if __name__ == "__main__":
    main()
