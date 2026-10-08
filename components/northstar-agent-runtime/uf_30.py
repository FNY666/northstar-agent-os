"""Largest component size by common factor.

Union indices whose numbers share a prime factor (via a factor -> first
index map). The answer is the largest DSU component size.
"""
import ast
import sys
from typing import Dict, List

UF_30_VERSION = "uf-30.v1"

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


def _factors(x: int) -> List[int]:
    fs = []
    d = 2
    while d * d <= x:
        if x % d == 0:
            fs.append(d)
            while x % d == 0:
                x //= d
        d += 1 if d == 2 else 2
    if x > 1:
        fs.append(x)
    return fs


def largest_factor_component(nums: List[int]) -> int:
    """Largest group of indices linked by a shared prime factor."""
    n = len(nums)
    uf = UnionFind(n)
    seen: Dict[int, int] = {}
    for i, v in enumerate(nums):
        for f in _factors(v):
            if f in seen:
                uf.union(i, seen[f])
            else:
                seen[f] = i
    return max(uf.size[uf.find(i)] for i in range(n)) if n else 0

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
    assert largest_factor_component([4, 6, 15, 35]) == 4
    assert largest_factor_component([20, 50, 9, 63]) == 2
    assert largest_factor_component([2, 3, 6, 7, 4, 12]) == 5
    assert largest_factor_component([1]) == 1
    assert largest_factor_component([]) == 0
    assert stdlib_only()
    print("uf-30 OK")


if __name__ == "__main__":
    main()
