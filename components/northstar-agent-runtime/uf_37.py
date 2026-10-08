"""Count unreachable pairs of nodes.

From component sizes, total pairs minus intra-component pairs gives the
number of pairs with no path between them.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_37_VERSION = "uf-37.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.size = [1] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]


def unreachable_pairs(n: int, edges: List[Tuple[int, int]]) -> int:
    """Count unordered node pairs with no connecting path."""
    uf = UnionFind(n)
    for a, b in edges:
        uf.union(a, b)
    sizes: Dict[int, int] = {}
    for i in range(n):
        r = uf.find(i)
        sizes[r] = sizes.get(r, 0) + 1
    total = n * (n - 1) // 2
    for s in sizes.values():
        total -= s * (s - 1) // 2
    return total

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
    assert unreachable_pairs(3, [(0, 1), (0, 2), (1, 2)]) == 0
    assert unreachable_pairs(7, [(0, 2), (0, 5), (2, 4), (1, 6), (5, 4)]) == 14
    assert unreachable_pairs(4, []) == 6
    assert unreachable_pairs(1, []) == 0
    assert stdlib_only()
    print("uf-37 OK")


if __name__ == "__main__":
    main()
