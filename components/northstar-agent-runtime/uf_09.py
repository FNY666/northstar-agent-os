"""Number of provinces from an adjacency matrix.

Two cities are in the same province when connected directly or
transitively. Union the upper triangle of the matrix and count roots.
"""
import ast
import sys
from typing import List

UF_09_VERSION = "uf-09.v1"

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


def find_provinces(is_connected: List[List[int]]) -> int:
    """Count provinces in an n x n adjacency matrix."""
    n = len(is_connected)
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if is_connected[i][j]:
                uf.union(i, j)
    return uf.components

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
    assert find_provinces([[1, 1, 0], [1, 1, 0], [0, 0, 1]]) == 2
    assert find_provinces([[1, 0, 0], [0, 1, 0], [0, 0, 1]]) == 3
    assert find_provinces([[1, 1, 1], [1, 1, 1], [1, 1, 1]]) == 1
    assert find_provinces([[1]]) == 1
    assert stdlib_only()
    print("uf-09 OK")


if __name__ == "__main__":
    main()
