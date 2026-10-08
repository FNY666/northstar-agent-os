"""Bricks falling when hit, solved in reverse.

Erase all hit bricks, build the DSU of what remains (with a virtual top
node), then re-add hits in reverse order. The number of bricks that
reconnect to the top, minus the restored brick itself, is the answer for
that hit.
"""
import ast
import sys
from typing import List, Tuple

UF_21_VERSION = "uf-21.v1"

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

    def size_of(self, x: int) -> int:
        return self.size[self.find(x)]


def hit_bricks(grid: List[List[int]], hits: List[Tuple[int, int]]) -> List[int]:
    """For each hit, count bricks that fall (excluding the hit brick)."""
    rows, cols = len(grid), len(grid[0])
    g = [row[:] for row in grid]
    for r, c in hits:
        g[r][c] = 0
    uf = UnionFind(rows * cols + 1)
    top = rows * cols

    def idx(r: int, c: int) -> int:
        return r * cols + c

    for r in range(rows):
        for c in range(cols):
            if not g[r][c]:
                continue
            if r == 0:
                uf.union(idx(r, c), top)
            if r > 0 and g[r - 1][c]:
                uf.union(idx(r, c), idx(r - 1, c))
            if c > 0 and g[r][c - 1]:
                uf.union(idx(r, c), idx(r, c - 1))
    ans = []
    for r, c in reversed(hits):
        if grid[r][c] == 0:
            ans.append(0)
            continue
        before = uf.size_of(top)
        g[r][c] = 1
        if r == 0:
            uf.union(idx(r, c), top)
        for dr, dc in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and g[nr][nc]:
                uf.union(idx(r, c), idx(nr, nc))
        ans.append(max(0, uf.size_of(top) - before - 1))
    return ans[::-1]

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
    assert hit_bricks([[1, 0, 0, 0], [1, 1, 1, 0]], [(1, 0)]) == [2]
    assert hit_bricks([[1, 0, 0, 0], [1, 1, 0, 0]], [(1, 1), (1, 0)]) == [0, 0]
    assert hit_bricks([[1]], [(0, 0)]) == [0]
    assert hit_bricks([[0]], [(0, 0)]) == [0]
    assert stdlib_only()
    print("uf-21 OK")


if __name__ == "__main__":
    main()
