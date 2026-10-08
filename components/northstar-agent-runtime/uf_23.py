"""Critical and pseudo-critical edges in an MST.

Compute the base MST weight. An edge is critical if excluding it raises
the MST weight (or disconnects); pseudo-critical if forcing it still
achieves the base weight without being critical.
"""
import ast
import sys
from typing import List, Tuple

UF_23_VERSION = "uf-23.v1"

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


def _mst(n: int, edges: List[Tuple[int, int, int, int]],
         skip: int, force: int) -> int:
    uf = UnionFind(n)
    cost, used = 0, 0
    if force >= 0:
        w, u, v, _ = edges[force]
        uf.union(u, v)
        cost, used = w, 1
    for i, (w, u, v, _) in enumerate(edges):
        if i == skip or i == force:
            continue
        if uf.union(u, v):
            cost += w
            used += 1
    return cost if used == n - 1 else 10 ** 18


def critical_edges(n: int, edges: List[Tuple[int, int, int]]
                   ) -> Tuple[List[int], List[int]]:
    """Return (critical, pseudo-critical) edge indices of the MST."""
    indexed = sorted(((w, u, v, i) for i, (u, v, w) in enumerate(edges)))
    base = _mst(n, indexed, -1, -1)
    critical, pseudo = [], []
    for pos in range(len(indexed)):
        if _mst(n, indexed, pos, -1) > base:
            critical.append(indexed[pos][3])
        elif _mst(n, indexed, -1, pos) == base:
            pseudo.append(indexed[pos][3])
    return sorted(critical), sorted(pseudo)

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
    ce, pe = critical_edges(5, [(0, 1, 1), (1, 2, 1), (2, 3, 2),
                                (0, 3, 2), (0, 4, 3), (3, 4, 3), (1, 4, 6)])
    assert ce == [0, 1]
    assert pe == [2, 3, 4, 5]
    ce2, pe2 = critical_edges(4, [(0, 1, 1), (1, 2, 1), (2, 3, 1), (0, 3, 1)])
    assert ce2 == []
    assert pe2 == [0, 1, 2, 3]
    assert stdlib_only()
    print("uf-23 OK")


if __name__ == "__main__":
    main()
