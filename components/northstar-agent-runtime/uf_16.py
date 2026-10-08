"""Min cost to connect all points (Manhattan MST via Kruskal).

Build all O(n^2) pairwise Manhattan edges, sort by weight, and run
Kruskal's algorithm: take an edge iff it connects two components.
"""
import ast
import sys
from typing import List, Tuple

UF_16_VERSION = "uf-16.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.components = n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[rb] = ra
        self.components -= 1
        return True


def min_cost_connect(points: List[Tuple[int, int]]) -> int:
    """MST weight over Manhattan distances between points."""
    n = len(points)
    edges = []
    for i in range(n):
        for j in range(i + 1, n):
            w = abs(points[i][0] - points[j][0]) + abs(points[i][1] - points[j][1])
            edges.append((w, i, j))
    edges.sort()
    uf = UnionFind(n)
    cost = 0
    for w, i, j in edges:
        if uf.union(i, j):
            cost += w
            if uf.components == 1:
                break
    return cost

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
    pts = [(0, 0), (2, 2), (3, 10), (5, 2), (7, 0)]
    assert min_cost_connect(pts) == 20
    assert min_cost_connect([(0, 0)]) == 0
    assert min_cost_connect([(0, 0), (1, 1)]) == 2
    assert min_cost_connect([(0, 0), (0, 1), (1, 0)]) == 2
    assert stdlib_only()
    print("uf-16 OK")


if __name__ == "__main__":
    main()
