"""Friend circles from a friendship edge list.

Direct analogue of provinces but driven by an explicit edge list instead
of a matrix: union every friendship, count the remaining components.
"""
import ast
import sys
from typing import List, Tuple

UF_11_VERSION = "uf-11.v1"

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


def friend_circles(n: int, friendships: List[Tuple[int, int]]) -> int:
    """Count friend circles among n people."""
    uf = UnionFind(n)
    for a, b in friendships:
        uf.union(a, b)
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
    assert friend_circles(4, [(0, 1), (2, 3)]) == 2
    assert friend_circles(4, [(0, 1), (1, 2), (2, 3)]) == 1
    assert friend_circles(3, []) == 3
    assert friend_circles(5, [(0, 4), (4, 2), (1, 3)]) == 2
    assert stdlib_only()
    print("uf-11 OK")


if __name__ == "__main__":
    main()
