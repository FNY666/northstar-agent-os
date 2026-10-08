"""Validate binary tree nodes.

A valid binary tree: every node except the root has exactly one parent,
there is exactly one root, and union-find sees no cycle (which together
with the parent counts guarantees a single connected tree).
"""
import ast
import sys
from typing import List

UF_47_VERSION = "uf-47.v1"

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


def valid_binary_tree(n: int, left: List[int], right: List[int]) -> bool:
    """True iff the child arrays describe a valid binary tree."""
    indeg = [0] * n
    uf = UnionFind(n)
    for p in range(n):
        for c in (left[p], right[p]):
            if c == -1:
                continue
            indeg[c] += 1
            if indeg[c] > 1:
                return False
            if not uf.union(p, c):
                return False
    roots = sum(1 for d in indeg if d == 0)
    return roots == 1 and uf.components == 1

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
    assert valid_binary_tree(4, [1, -1, 3, -1], [2, -1, -1, -1]) is True
    assert valid_binary_tree(4, [1, -1, 3, -1], [2, 3, -1, -1]) is False
    assert valid_binary_tree(2, [1, 0], [-1, -1]) is False
    assert valid_binary_tree(1, [-1], [-1]) is True
    assert stdlib_only()
    print("uf-47 OK")


if __name__ == "__main__":
    main()
