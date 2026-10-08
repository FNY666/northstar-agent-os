"""Number of islands II: dynamic land additions.

Maintain parent pointers only for cells that have become land. Each new
land cell starts as its own island and merges with land neighbours.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_38_VERSION = "uf-38.v1"

class UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[int, int] = {}
        self.components = 0

    def add(self, x: int) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.components += 1

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> bool:
        if a not in self.parent or b not in self.parent:
            return False
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.parent[rb] = ra
        self.components -= 1
        return True


def islands_ii(m: int, n: int,
               positions: List[Tuple[int, int]]) -> List[int]:
    """Island count after each land addition."""
    uf = UnionFind()
    ans = []
    for r, c in positions:
        i = r * n + c
        if i in uf.parent:
            ans.append(uf.components)
            continue
        uf.add(i)
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < m and 0 <= nc < n:
                uf.union(i, nr * n + nc)
        ans.append(uf.components)
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
    assert islands_ii(3, 3, [(0, 0), (0, 1), (1, 2), (2, 1)]) == [1, 1, 2, 3]
    assert islands_ii(1, 1, [(0, 0)]) == [1]
    assert islands_ii(2, 2, [(0, 0), (0, 0), (1, 1)]) == [1, 1, 2]
    assert stdlib_only()
    print("uf-38 OK")


if __name__ == "__main__":
    main()
