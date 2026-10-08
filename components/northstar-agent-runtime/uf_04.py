"""Redundant connection: find the edge that closes a cycle.

Scan edges in order; the first edge whose endpoints are already connected
is the redundant one. Returns (-1, -1) when the graph is a forest.
"""
import ast
import sys
from typing import List, Tuple

UF_04_VERSION = "uf-04.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

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
        return True


def find_redundant(n: int, edges: List[Tuple[int, int]]) -> Tuple[int, int]:
    """Return the first edge that forms a cycle, or (-1, -1)."""
    uf = UnionFind(n + 1)
    for a, b in edges:
        if not uf.union(a, b):
            return (a, b)
    return (-1, -1)

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
    assert find_redundant(3, [(1, 2), (1, 3), (2, 3)]) == (2, 3)
    assert find_redundant(5, [(1, 2), (2, 3), (3, 4), (1, 4), (1, 5)]) == (1, 4)
    assert find_redundant(2, [(1, 2)]) == (-1, -1)
    assert find_redundant(4, [(1, 2), (2, 3), (3, 1), (1, 4)]) == (3, 1)
    assert stdlib_only()
    print("uf-04 OK")


if __name__ == "__main__":
    main()
