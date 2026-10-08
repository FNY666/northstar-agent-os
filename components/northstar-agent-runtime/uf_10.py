"""Most stones removed with shared row or column.

Model each stone as a node; union stones sharing a row or a column via
first-seen maps. A component of k stones can lose k-1 of them, so the
answer is n minus the component count.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_10_VERSION = "uf-10.v1"

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


def remove_stones(stones: List[Tuple[int, int]]) -> int:
    """Max stones removable when sharing a row or column allows removal."""
    n = len(stones)
    uf = UnionFind(n)
    seen_x: Dict[int, int] = {}
    seen_y: Dict[int, int] = {}
    for i, (x, y) in enumerate(stones):
        if x in seen_x:
            uf.union(i, seen_x[x])
        else:
            seen_x[x] = i
        if y in seen_y:
            uf.union(i, seen_y[y])
        else:
            seen_y[y] = i
    return n - uf.components

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
    s1 = [(0, 0), (0, 1), (1, 0), (1, 2), (2, 1), (2, 2)]
    assert remove_stones(s1) == 5
    assert remove_stones([(0, 0), (0, 2), (1, 1), (2, 0), (2, 2)]) == 3
    assert remove_stones([(0, 0)]) == 0
    assert remove_stones([]) == 0
    assert stdlib_only()
    print("uf-10 OK")


if __name__ == "__main__":
    main()
