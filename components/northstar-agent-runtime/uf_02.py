"""Union-find with union by size.

Variant of DSU that keeps an explicit subtree size and always attaches the
smaller tree under the larger one. ``size_of`` answers component-size
queries in (amortized) constant time.
"""
import ast
import sys

UF_02_VERSION = "uf-02.v1"

class UnionFind:
    """Disjoint-set union with path compression and union by size."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.size = [1] * n
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
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        self.components -= 1
        return True

    def size_of(self, x: int) -> int:
        return self.size[self.find(x)]

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
    uf = UnionFind(6)
    uf.union(0, 1)
    uf.union(2, 3)
    uf.union(4, 5)
    assert uf.size_of(0) == 2
    uf.union(1, 2)
    assert uf.size_of(3) == 4
    assert uf.size_of(5) == 2
    assert uf.components == 2
    assert uf.union(0, 3) is False
    assert uf.find(1) == uf.find(2)
    assert stdlib_only()
    print("uf-02 OK")


if __name__ == "__main__":
    main()
