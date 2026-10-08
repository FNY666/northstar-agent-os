"""Generic Kruskal MST.

Sort (weight, u, v) edges increasingly and greedily take every edge that
joins two different components. Returns -1 when the graph is disconnected.
"""
import ast
import sys
from typing import List, Tuple

UF_17_VERSION = "uf-17.v1"

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


def kruskal(n: int, edges: List[Tuple[int, int, int]]) -> int:
    """MST total weight for edges (w, u, v); -1 if disconnected."""
    uf = UnionFind(n)
    cost = 0
    for w, u, v in sorted(edges):
        if uf.union(u, v):
            cost += w
    return cost if uf.components == 1 else -1

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
    assert kruskal(4, [(1, 0, 1), (2, 1, 2), (3, 2, 3), (4, 0, 3)]) == 6
    assert kruskal(3, [(5, 0, 1)]) == -1
    assert kruskal(1, []) == 0
    assert kruskal(3, [(1, 0, 1), (1, 1, 2), (10, 0, 2)]) == 2
    assert stdlib_only()
    print("uf-17 OK")


if __name__ == "__main__":
    main()
