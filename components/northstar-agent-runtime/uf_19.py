"""Regions cut by slashes.

Split each cell into 4 triangles (0 top, 1 right, 2 bottom, 3 left).
A space unions all four; '/' unions (0,3) and (1,2); backslash unions
(0,1) and (2,3). Neighbouring cells share triangle borders. The region
count is the number of distinct DSU roots.
"""
import ast
import sys
from typing import List

UF_19_VERSION = "uf-19.v1"

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


def regions_by_slashes(grid: List[str]) -> int:
    """Count regions formed by '/' and backslash walls in a grid."""
    n = len(grid)
    uf = UnionFind(4 * n * n)

    def idx(r: int, c: int, k: int) -> int:
        return 4 * (r * n + c) + k

    for r in range(n):
        for c in range(n):
            ch = grid[r][c]
            if ch == " ":
                uf.union(idx(r, c, 0), idx(r, c, 1))
                uf.union(idx(r, c, 1), idx(r, c, 2))
                uf.union(idx(r, c, 2), idx(r, c, 3))
            elif ch == "/":
                uf.union(idx(r, c, 0), idx(r, c, 3))
                uf.union(idx(r, c, 1), idx(r, c, 2))
            else:  # backslash
                uf.union(idx(r, c, 0), idx(r, c, 1))
                uf.union(idx(r, c, 2), idx(r, c, 3))
            if r + 1 < n:
                uf.union(idx(r, c, 2), idx(r + 1, c, 0))
            if c + 1 < n:
                uf.union(idx(r, c, 1), idx(r, c + 1, 3))
    roots = set()
    for r in range(n):
        for c in range(n):
            for k in range(4):
                roots.add(uf.find(idx(r, c, k)))
    return len(roots)

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
    assert regions_by_slashes([" /", "/ "]) == 2
    assert regions_by_slashes([" /", "  "]) == 1
    assert regions_by_slashes(["/\\", "\\/"]) == 5
    assert regions_by_slashes([" "]) == 1
    assert stdlib_only()
    print("uf-19 OK")


if __name__ == "__main__":
    main()
