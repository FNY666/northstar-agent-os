"""Operations to make the network connected.

Count redundant edges (unions that fail) and components. We need
components - 1 cables, feasible iff redundant edges cover the deficit.
"""
import ast
import sys
from typing import List, Tuple

UF_32_VERSION = "uf-32.v1"

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


def make_connected(n: int, connections: List[Tuple[int, int]]) -> int:
    """Min cable moves to connect n computers; -1 if impossible."""
    if len(connections) < n - 1:
        return -1
    uf = UnionFind(n)
    for a, b in connections:
        uf.union(a, b)
    return uf.components - 1

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
    assert make_connected(4, [(0, 1), (0, 2), (1, 2)]) == 1
    assert make_connected(6, [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3)]) == 2
    assert make_connected(6, [(0, 1), (0, 2), (0, 3), (1, 2)]) == -1
    assert make_connected(1, []) == 0
    assert stdlib_only()
    print("uf-32 OK")


if __name__ == "__main__":
    main()
