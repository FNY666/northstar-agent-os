"""Redundant connection II: directed graphs.

A valid rooted tree has indegree <= 1 everywhere and no cycle. If some
node has two parents, the answer is one of those two edges (the later one
when removing it fixes the tree, else the earlier); otherwise it is the
edge that closes a directed cycle.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_41_VERSION = "uf-41.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

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
        return True


def _forms_tree(n: int, edges: List[Tuple[int, int]],
                skip: Tuple[int, int]) -> bool:
    uf = UnionFind(n + 1)
    for e in edges:
        if e == skip:
            continue
        if not uf.union(e[0], e[1]):
            return False
    return True


def redundant_directed(edges: List[Tuple[int, int]]) -> List[int]:
    """Find the redundant directed edge in an almost-tree."""
    parent: Dict[int, Tuple[int, int]] = {}
    cand1: Tuple[int, int] = (-1, -1)
    cand2: Tuple[int, int] = (-1, -1)
    for u, v in edges:
        if v in parent:
            cand1, cand2 = parent[v], (u, v)
        else:
            parent[v] = (u, v)
    n = len(edges)
    if cand1 != (-1, -1):
        if _forms_tree(n, edges, cand2):
            return [cand2[0], cand2[1]]
        return [cand1[0], cand1[1]]
    uf = UnionFind(n + 1)
    for u, v in edges:
        if not uf.union(u, v):
            return [u, v]
    return []

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
    assert redundant_directed([(1, 2), (1, 3), (2, 3)]) == [2, 3]
    assert redundant_directed([(1, 2), (2, 3), (3, 4), (4, 1), (1, 5)]) == [4, 1]
    assert redundant_directed([(2, 1), (3, 1), (4, 2), (1, 4)]) == [2, 1]
    assert redundant_directed([(1, 2), (2, 3), (3, 1)]) == [3, 1]
    assert stdlib_only()
    print("uf-41 OK")


if __name__ == "__main__":
    main()
