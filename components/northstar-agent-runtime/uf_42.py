"""Count servers that communicate.

Two servers communicate when they share a row or column. Union servers in
the same row/column, then count servers living in components of size > 1.
"""
import ast
import sys
from typing import Dict, List

UF_42_VERSION = "uf-42.v1"

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


def count_servers(grid: List[List[int]]) -> int:
    """Servers that can communicate with at least one other server."""
    rows, cols = len(grid), len(grid[0])
    uf = UnionFind(rows * cols)
    for r in range(rows):
        first = -1
        for c in range(cols):
            if grid[r][c]:
                if first >= 0:
                    uf.union(first, r * cols + c)
                else:
                    first = r * cols + c
    for c in range(cols):
        first = -1
        for r in range(rows):
            if grid[r][c]:
                if first >= 0:
                    uf.union(first, r * cols + c)
                else:
                    first = r * cols + c
    comp: Dict[int, int] = {}
    for r in range(rows):
        for c in range(cols):
            if grid[r][c]:
                root = uf.find(r * cols + c)
                comp[root] = uf.size[root]
    return sum(1 for r in range(rows) for c in range(cols)
               if grid[r][c] and comp[uf.find(r * cols + c)] > 1)

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
    assert count_servers([[1, 0], [0, 1]]) == 0
    assert count_servers([[1, 0], [1, 1]]) == 3
    assert count_servers([[1, 1, 1, 1]]) == 4
    assert count_servers([[0, 0], [0, 0]]) == 0
    assert stdlib_only()
    print("uf-42 OK")


if __name__ == "__main__":
    main()
