"""Minimum score of a path between two cities.

The best path's score is the minimum edge weight along it; maximizing
that minimum over paths equals the minimum edge in the connected
component of city 1 (which must contain city n).
"""
import ast
import sys
from typing import List, Tuple

UF_45_VERSION = "uf-45.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n + 1))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def min_path_score(n: int, roads: List[Tuple[int, int, int]]) -> int:
    """Maximin edge score on any path from 1 to n."""
    uf = UnionFind(n)
    for a, b, _ in roads:
        uf.union(a, b)
    root = uf.find(1)
    return min(w for a, b, w in roads
               if uf.find(a) == root and uf.find(b) == root)

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
    assert min_path_score(4, [(1, 2, 9), (2, 3, 6), (2, 4, 5), (1, 4, 7)]) == 5
    assert min_path_score(4, [(1, 2, 2), (1, 3, 4), (3, 4, 7)]) == 2
    assert min_path_score(2, [(1, 2, 100)]) == 100
    assert stdlib_only()
    print("uf-45 OK")


if __name__ == "__main__":
    main()
