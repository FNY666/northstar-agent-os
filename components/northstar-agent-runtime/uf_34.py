"""Remove max edges to keep the graph fully traversable.

Alice and Bob share type-3 edges but need their own connectivity over
type-1 / type-2 edges. Process type-3 first on both DSUs, then the rest;
answer = total edges - used edges, or -1 when someone stays disconnected.
"""
import ast
import sys
from typing import List, Tuple

UF_34_VERSION = "uf-34.v1"

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


def max_removable(n: int, edges: List[Tuple[int, int, int]]) -> int:
    """Max removable edges keeping Alice's and Bob's graphs connected."""
    alice, bob = UnionFind(n + 1), UnionFind(n + 1)
    used = 0
    for t, u, v in edges:
        if t == 3:
            a = alice.union(u, v)
            b = bob.union(u, v)
            if a or b:
                used += 1
    for t, u, v in edges:
        if t == 1 and alice.union(u, v):
            used += 1
        elif t == 2 and bob.union(u, v):
            used += 1
    if alice.components != 2 or bob.components != 2:
        return -1
    return len(edges) - used

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
    e = [(3, 1, 2), (3, 2, 3), (1, 1, 3), (1, 2, 4), (1, 1, 2), (2, 3, 4)]
    assert max_removable(4, e) == 2
    assert max_removable(4, [(3, 1, 2), (3, 2, 3), (1, 1, 4), (2, 1, 4)]) == 0
    assert max_removable(4, [(3, 2, 3), (1, 1, 2), (2, 3, 4)]) == -1
    assert stdlib_only()
    print("uf-34 OK")


if __name__ == "__main__":
    main()
