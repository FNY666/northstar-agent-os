"""Minimize malware spread.

Union the whole graph, then for each initially infected node look at its
component size. Infecting the node whose component is largest (and unique)
saves the most nodes; ties break toward the smallest index.
"""
import ast
import sys
from typing import Dict, List

UF_20_VERSION = "uf-20.v1"

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


def min_malware_spread(graph: List[List[int]], initial: List[int]) -> int:
    """Pick the initial node whose removal minimizes total infection."""
    n = len(graph)
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if graph[i][j]:
                uf.union(i, j)
    comp_size: Dict[int, int] = {}
    for i in range(n):
        r = uf.find(i)
        comp_size[r] = comp_size.get(r, 0) + 1
    infected: Dict[int, int] = {}
    for v in initial:
        r = uf.find(v)
        infected[r] = infected.get(r, 0) + 1
    best, best_saved = min(initial), -1
    for v in initial:
        r = uf.find(v)
        if infected[r] == 1:
            saved = comp_size[r]
            if saved > best_saved or (saved == best_saved and v < best):
                best, best_saved = v, saved
    return best

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
    g = [[1, 1, 0], [1, 1, 0], [0, 0, 1]]
    assert min_malware_spread(g, [0, 1]) == 0
    assert min_malware_spread(g, [0, 2]) == 0
    g2 = [[1, 1, 0, 0], [1, 1, 1, 0], [0, 1, 1, 0], [0, 0, 0, 1]]
    assert min_malware_spread(g2, [0, 1, 3]) == 3
    assert min_malware_spread([[1]], [0]) == 0
    assert stdlib_only()
    print("uf-20 OK")


if __name__ == "__main__":
    main()
