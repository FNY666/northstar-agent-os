"""Swim in rising water.

Activate cells in order of increasing height, unioning each with already
active neighbours. The moment start connects to target, the current
height is the minimal possible maximum elevation.
"""
import ast
import sys
from typing import List

UF_27_VERSION = "uf-27.v1"

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


def swim(grid: List[List[int]]) -> int:
    """Minimum time to swim from top-left to bottom-right."""
    n = len(grid)
    order = sorted(((grid[r][c], r, c) for r in range(n) for c in range(n)))
    uf = UnionFind(n * n)
    active = [[False] * n for _ in range(n)]
    for h, r, c in order:
        active[r][c] = True
        i = r * n + c
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < n and 0 <= nc < n and active[nr][nc]:
                uf.union(i, nr * n + nc)
        if uf.connected(0, n * n - 1):
            return h
    return -1

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
    assert swim([[0, 2], [1, 3]]) == 3
    assert swim([[0, 1, 2, 3, 4], [24, 23, 22, 21, 5], [12, 13, 14, 15, 16],
                 [11, 17, 18, 19, 20], [10, 9, 8, 7, 6]]) == 16
    assert swim([[0]]) == 0
    assert swim([[3, 2], [0, 1]]) == 3
    assert stdlib_only()
    print("uf-27 OK")


if __name__ == "__main__":
    main()
