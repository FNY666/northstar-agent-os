"""Kruskal with pre-existing connections.

Some pairs are already connected for free. Seed the DSU with those unions
first, then run Kruskal over the remaining candidate edges.
"""
import ast
import sys
from typing import List, Tuple

UF_44_VERSION = "uf-44.v1"

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


def kruskal_seeded(n: int, free: List[Tuple[int, int]],
                   edges: List[Tuple[int, int, int]]) -> int:
    """MST weight given free pre-connected pairs; -1 if disconnected."""
    uf = UnionFind(n)
    for a, b in free:
        uf.union(a, b)
    cost = 0
    for w, u, v in sorted(edges):
        if uf.union(u, v):
            cost += w
            if uf.components == 1:
                break
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
    assert kruskal_seeded(4, [(0, 1)], [(5, 1, 2), (3, 2, 3), (9, 0, 3)]) == 8
    assert kruskal_seeded(3, [], [(1, 0, 1), (1, 1, 2)]) == 2
    assert kruskal_seeded(3, [(0, 1), (1, 2)], []) == 0
    assert kruskal_seeded(3, [], [(1, 0, 1)]) == -1
    assert stdlib_only()
    print("uf-44 OK")


if __name__ == "__main__":
    main()
