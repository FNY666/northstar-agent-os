"""Graph valid tree check.

An undirected graph is a tree iff it has exactly n-1 edges and no cycle.
Union-find detects the cycle in one pass; the edge count rules out
disconnected forests.
"""
import ast
import sys
from typing import List, Tuple

UF_07_VERSION = "uf-07.v1"

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


def valid_tree(n: int, edges: List[Tuple[int, int]]) -> bool:
    """True iff the edges form a valid tree over n nodes."""
    if len(edges) != n - 1:
        return False
    uf = UnionFind(n)
    for a, b in edges:
        if not uf.union(a, b):
            return False
    return uf.components == 1

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
    assert valid_tree(5, [(0, 1), (0, 2), (0, 3), (1, 4)]) is True
    assert valid_tree(5, [(0, 1), (1, 2), (2, 3), (1, 3), (1, 4)]) is False
    assert valid_tree(1, []) is True
    assert valid_tree(2, [(0, 1)]) is True
    assert valid_tree(3, [(0, 1)]) is False
    assert stdlib_only()
    print("uf-07 OK")


if __name__ == "__main__":
    main()
