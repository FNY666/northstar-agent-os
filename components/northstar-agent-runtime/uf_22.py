"""Min cost to supply water.

Add a virtual node 0 with an edge (0, i) weighted by well cost for each
house i, then run Kruskal over wells plus pipes.
"""
import ast
import sys
from typing import List, Tuple

UF_22_VERSION = "uf-22.v1"

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


def min_water_cost(n: int, wells: List[int],
                   pipes: List[Tuple[int, int, int]]) -> int:
    """Cheapest way to water n houses (1-indexed) via wells or pipes."""
    edges = [(w, 0, i) for i, w in enumerate(wells, start=1)]
    for u, v, w in pipes:
        edges.append((w, u, v))
    uf = UnionFind(n + 1)
    cost = 0
    for w, u, v in sorted(edges):
        if uf.union(u, v):
            cost += w
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
    assert min_water_cost(3, [1, 2, 2], [(1, 2, 1), (2, 3, 1)]) == 3
    assert min_water_cost(2, [5, 5], [(1, 2, 1)]) == 6
    assert min_water_cost(1, [7], []) == 7
    assert stdlib_only()
    print("uf-22 OK")


if __name__ == "__main__":
    main()
