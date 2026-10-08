"""Minimum Hamming distance after allowed swaps.

Union swappable index pairs; within each component the multiset of source
characters can be permuted freely, so mismatches = size - matches with the
target multiset.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_26_VERSION = "uf-26.v1"

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


def min_hamming(source: str, target: str,
                swaps: List[Tuple[int, int]]) -> int:
    """Min Hamming distance after arbitrary swaps within components."""
    n = len(source)
    uf = UnionFind(n)
    for a, b in swaps:
        uf.union(a, b)
    groups: Dict[int, List[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)
    ans = 0
    for idxs in groups.values():
        have: Dict[str, int] = {}
        want: Dict[str, int] = {}
        for i in idxs:
            have[source[i]] = have.get(source[i], 0) + 1
            want[target[i]] = want.get(target[i], 0) + 1
        match = sum(min(have.get(c, 0), want.get(c, 0)) for c in have)
        ans += len(idxs) - match
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
    assert min_hamming("abcd", "cdab", [(0, 2), (1, 3)]) == 0
    assert min_hamming("abcd", "abdc", []) == 2
    assert min_hamming("aaa", "aaa", [(0, 1)]) == 0
    assert min_hamming("ab", "ba", [(0, 1)]) == 0
    assert stdlib_only()
    print("uf-26 OK")


if __name__ == "__main__":
    main()
