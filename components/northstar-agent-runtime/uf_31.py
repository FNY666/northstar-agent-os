"""GCD sort of an array.

Union indices whose values share a prime factor; any permutation inside a
component is achievable. The array is sortable iff every component's value
multiset matches the multiset the sorted array demands there.
"""
import ast
import sys
from typing import Dict, List

UF_31_VERSION = "uf-31.v1"

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


def gcd_sortable(nums: List[int]) -> bool:
    """True iff swaps along shared-factor links can sort the array."""
    n = len(nums)
    uf = UnionFind(n)
    seen: Dict[int, int] = {}
    for i, v in enumerate(nums):
        for f in _factors(v):
            if f in seen:
                uf.union(i, seen[f])
            else:
                seen[f] = i
    target = sorted(nums)
    groups: Dict[int, List[int]] = {}
    tgroups: Dict[int, List[int]] = {}
    for i in range(n):
        r = uf.find(i)
        groups.setdefault(r, []).append(nums[i])
        tgroups.setdefault(r, []).append(target[i])
    return all(sorted(groups[r]) == sorted(tgroups[r]) for r in groups)

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
    assert gcd_sortable([7, 21, 3]) is True
    assert gcd_sortable([5, 2, 6, 2]) is False
    assert gcd_sortable([10, 5, 9, 3, 15]) is True
    assert gcd_sortable([1]) is True
    assert stdlib_only()
    print("uf-31 OK")


if __name__ == "__main__":
    main()
