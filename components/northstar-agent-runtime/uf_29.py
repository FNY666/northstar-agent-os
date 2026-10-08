"""Making a large island.

Label each land component via DSU, then try flipping every water cell:
the resulting island is 1 plus the sum of distinct neighbouring component
sizes. The max over all flips (and the all-land case) wins.
"""
import ast
import sys
from typing import Dict, List

UF_29_VERSION = "uf-29.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.size = [1] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]


def largest_island(grid: List[List[int]]) -> int:
    """Largest island area after flipping at most one 0 to 1."""
    n = len(grid)
    uf = UnionFind(n * n)

    def idx(r: int, c: int) -> int:
        return r * n + c

    for r in range(n):
        for c in range(n):
            if not grid[r][c]:
                continue
            if r > 0 and grid[r - 1][c]:
                uf.union(idx(r, c), idx(r - 1, c))
            if c > 0 and grid[r][c - 1]:
                uf.union(idx(r, c), idx(r, c - 1))
    comp: Dict[int, int] = {}
    for r in range(n):
        for c in range(n):
            if grid[r][c]:
                root = uf.find(idx(r, c))
                comp[root] = uf.size[root]
    best = max(comp.values()) if comp else 0
    for r in range(n):
        for c in range(n):
            if grid[r][c]:
                continue
            seen = set()
            area = 1
            for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                nr, nc = r + dr, c + dc
                if 0 <= nr < n and 0 <= nc < n and grid[nr][nc]:
                    root = uf.find(idx(nr, nc))
                    if root not in seen:
                        seen.add(root)
                        area += comp[root]
            best = max(best, area)
    return best

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
    assert largest_island([[1, 0], [0, 1]]) == 3
    assert largest_island([[1, 1], [1, 0]]) == 4
    assert largest_island([[1, 1], [1, 1]]) == 4
    assert largest_island([[0, 0], [0, 0]]) == 1
    assert stdlib_only()
    print("uf-29 OK")


if __name__ == "__main__":
    main()
