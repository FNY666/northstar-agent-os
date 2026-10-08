"""Distance-limited path queries, answered offline.

Sort edges by distance and queries by limit; sweep the limit upward,
unioning edges as they become usable, then answer each query by a
connectivity check.
"""
import ast
import sys
from typing import List, Tuple

UF_24_VERSION = "uf-24.v1"

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

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)


def limited_paths(n: int, edges: List[Tuple[int, int, int]],
                  queries: List[Tuple[int, int, int]]) -> List[bool]:
    """For each (p, q, limit): is there a path using edges < limit?"""
    edges = sorted(edges, key=lambda e: e[2])
    order = sorted(range(len(queries)), key=lambda i: queries[i][2])
    uf = UnionFind(n)
    ans = [False] * len(queries)
    ei = 0
    for qi in order:
        p, q, limit = queries[qi]
        while ei < len(edges) and edges[ei][2] < limit:
            uf.union(edges[ei][0], edges[ei][1])
            ei += 1
        ans[qi] = uf.connected(p, q)
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
    e = [(0, 1, 2), (1, 2, 4), (2, 0, 8), (1, 0, 16)]
    q = [(0, 1, 2), (0, 2, 5)]
    assert limited_paths(3, e, q) == [False, True]
    assert limited_paths(2, [], [(0, 1, 10)]) == [False]
    assert limited_paths(2, [(0, 1, 3)], [(0, 1, 3)]) == [False]
    assert limited_paths(2, [(0, 1, 3)], [(0, 1, 4)]) == [True]
    assert stdlib_only()
    print("uf-24 OK")


if __name__ == "__main__":
    main()
