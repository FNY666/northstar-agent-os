"""Number of islands via union-find.

Treat every land cell as a node; union it with its upper and left land
neighbours. Maintain a live land counter that drops on each successful
merge, so no second pass over the grid is needed.
"""
import ast
import sys
from typing import List

UF_05_VERSION = "uf-05.v1"

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


def num_islands(grid: List[List[str]]) -> int:
    """Count 4-connected islands of "1" cells."""
    if not grid or not grid[0]:
        return 0
    rows, cols = len(grid), len(grid[0])
    uf = UnionFind(rows * cols)
    land = 0
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] != "1":
                continue
            land += 1
            i = r * cols + c
            if r > 0 and grid[r - 1][c] == "1":
                if uf.union(i, (r - 1) * cols + c):
                    land -= 1
            if c > 0 and grid[r][c - 1] == "1":
                if uf.union(i, r * cols + c - 1):
                    land -= 1
    return land

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
    g1 = [["1", "1", "0"], ["1", "0", "0"], ["0", "0", "1"]]
    assert num_islands(g1) == 2
    g2 = [["1", "1", "1"], ["0", "1", "0"], ["1", "1", "1"]]
    assert num_islands(g2) == 1
    assert num_islands([["0", "0"], ["0", "0"]]) == 0
    assert num_islands([]) == 0
    assert num_islands([["1"]]) == 1
    assert stdlib_only()
    print("uf-05 OK")


if __name__ == "__main__":
    main()
