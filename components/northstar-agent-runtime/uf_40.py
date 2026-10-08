"""Smallest string with swaps.

Union swappable index pairs; within each component, sort the characters
and place them back at the sorted indices for the lexicographically
smallest result.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_40_VERSION = "uf-40.v1"

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


def smallest_with_swaps(s: str, pairs: List[Tuple[int, int]]) -> str:
    """Lexicographically smallest string after allowed swaps."""
    n = len(s)
    uf = UnionFind(n)
    for a, b in pairs:
        uf.union(a, b)
    groups: Dict[int, List[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)
    out = [""] * n
    for idxs in groups.values():
        chars = sorted(s[i] for i in idxs)
        for i, ch in zip(sorted(idxs), chars):
            out[i] = ch
    return "".join(out)

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
    assert smallest_with_swaps("dcab", [(0, 3), (1, 2)]) == "bacd"
    assert smallest_with_swaps("dcab", [(0, 3), (1, 2), (0, 2)]) == "abcd"
    assert smallest_with_swaps("cba", [(0, 1), (1, 2)]) == "abc"
    assert smallest_with_swaps("abc", []) == "abc"
    assert stdlib_only()
    print("uf-40 OK")


if __name__ == "__main__":
    main()
