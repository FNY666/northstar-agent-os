"""Connected components from an adjacency list.

Same counting idea as the edge-list version but driven by an adjacency
dictionary, which is the more common in-memory graph representation.
"""
import ast
import sys
from typing import Dict, List

UF_15_VERSION = "uf-15.v1"

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


def components_from_adj(n: int, adj: Dict[int, List[int]]) -> int:
    """Count components of a graph given as an adjacency dict."""
    uf = UnionFind(n)
    for u, nbrs in adj.items():
        for v in nbrs:
            uf.union(u, v)
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
    assert components_from_adj(5, {0: [1], 1: [0, 2], 3: [4]}) == 2
    assert components_from_adj(3, {}) == 3
    assert components_from_adj(1, {0: []}) == 1
    assert components_from_adj(4, {0: [1, 2, 3]}) == 1
    assert stdlib_only()
    print("uf-15 OK")


if __name__ == "__main__":
    main()
