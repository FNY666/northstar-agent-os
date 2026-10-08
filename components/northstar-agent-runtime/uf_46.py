"""Count complete connected components.

A component with k vertices is complete iff it holds exactly k*(k-1)/2
edges. Union all edges while tallying per-root vertex and edge counts.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_46_VERSION = "uf-46.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def complete_components(n: int, edges: List[Tuple[int, int]]) -> int:
    """Count connected components that are complete graphs."""
    uf = UnionFind(n)
    for a, b in edges:
        uf.union(a, b)
    verts: Dict[int, int] = {}
    edgec: Dict[int, int] = {}
    for i in range(n):
        r = uf.find(i)
        verts[r] = verts.get(r, 0) + 1
    for a, _ in edges:
        r = uf.find(a)
        edgec[r] = edgec.get(r, 0) + 1
    ans = 0
    for r, k in verts.items():
        if edgec.get(r, 0) == k * (k - 1) // 2:
            ans += 1
    return ans

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
    assert complete_components(6, [(0, 1), (0, 2), (1, 2), (3, 4)]) == 3
    assert complete_components(6, [(0, 1), (0, 2), (1, 2), (3, 4), (4, 5),
                                  (3, 5)]) == 2
    assert complete_components(3, []) == 3
    assert complete_components(2, [(0, 1)]) == 1
    assert stdlib_only()
    print("uf-46 OK")


if __name__ == "__main__":
    main()
