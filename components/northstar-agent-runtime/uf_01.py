"""Basic union-find: path compression plus union by rank.

The canonical disjoint-set union (DSU) data structure. ``find`` compresses
the path with two passes (halving on the way up, flattening on the way
down); ``union`` attaches the lower-rank tree under the higher-rank one.
Near-constant amortized time per operation (inverse Ackermann).
"""
import ast
import sys

UF_01_VERSION = "uf-01.v1"

class UnionFind:
    """Disjoint-set union with path compression and union by rank."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.rank = [0] * n
        self.components = n

    def find(self, x: int) -> int:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> bool:
        """Merge the sets of ``a`` and ``b``; False when already united."""
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        self.components -= 1
        return True

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)

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
    uf = UnionFind(5)
    assert uf.components == 5
    assert uf.union(0, 1) is True
    assert uf.union(0, 1) is False
    assert uf.connected(0, 1)
    assert not uf.connected(0, 2)
    uf.union(2, 3)
    uf.union(1, 2)
    assert uf.connected(0, 3)
    assert uf.components == 2
    assert uf.find(0) == uf.find(3)
    assert stdlib_only()
    print("uf-01 OK")


if __name__ == "__main__":
    main()
