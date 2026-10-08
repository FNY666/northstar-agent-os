"""Path with minimum effort via Kruskal-style expansion.

Turn every adjacent cell pair into an edge weighted by height difference,
sort increasingly, and union until start connects to target. The edge that
connects them is the minimal possible maximum effort.
"""
import ast
import sys
from typing import List

UF_33_VERSION = "uf-33.v1"

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


def min_effort(heights: List[List[int]]) -> int:
    """Minimize the maximum height difference along any path."""
    rows, cols = len(heights), len(heights[0])
    edges = []
    for r in range(rows):
        for c in range(cols):
            i = r * cols + c
            if r + 1 < rows:
                edges.append((abs(heights[r][c] - heights[r + 1][c]),
                              i, (r + 1) * cols + c))
            if c + 1 < cols:
                edges.append((abs(heights[r][c] - heights[r][c + 1]),
                              i, r * cols + c + 1))
    edges.sort()
    uf = UnionFind(rows * cols)
    for w, a, b in edges:
        uf.union(a, b)
        if uf.connected(0, rows * cols - 1):
            return w
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
    assert min_effort([[1, 2, 2], [3, 8, 2], [5, 3, 5]]) == 2
    assert min_effort([[1, 2, 3], [3, 8, 4], [5, 3, 5]]) == 1
    assert min_effort([[1, 2, 1, 1, 1], [1, 2, 1, 2, 1],
                       [1, 2, 1, 2, 1], [1, 2, 1, 2, 1],
                       [1, 1, 1, 2, 1]]) == 0
    assert min_effort([[5]]) == 0
    assert stdlib_only()
    print("uf-33 OK")


if __name__ == "__main__":
    main()
