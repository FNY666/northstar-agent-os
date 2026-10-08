"""Couples holding hands: minimum swaps.

Couple k sits at seats 2k and 2k+1 ideally. Union the couples occupying
each adjacent seat pair; a component of k couples needs k-1 swaps, so the
answer is (#couples) - (#components).
"""
import ast
import sys
from typing import List

UF_12_VERSION = "uf-12.v1"

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


def min_swaps_couples(row: List[int]) -> int:
    """Minimum swaps so every couple sits adjacently."""
    n = len(row) // 2
    uf = UnionFind(n)
    for i in range(0, len(row), 2):
        uf.union(row[i] // 2, row[i + 1] // 2)
    return n - uf.components

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
    assert min_swaps_couples([0, 2, 1, 3]) == 1
    assert min_swaps_couples([3, 2, 0, 1]) == 0
    assert min_swaps_couples([0, 1, 2, 3]) == 0
    assert min_swaps_couples([1, 4, 0, 2, 3, 5]) == 2
    assert stdlib_only()
    print("uf-12 OK")


if __name__ == "__main__":
    main()
