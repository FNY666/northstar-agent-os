"""Number of similar string groups.

Two strings are similar when equal or differing in exactly two positions
(a single swap makes them equal). Union all similar pairs; the group
count is the number of DSU components.
"""
import ast
import sys
from typing import List

UF_35_VERSION = "uf-35.v1"

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


def _similar(a: str, b: str) -> bool:
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 0 or (len(diff) == 2 and
                             a[diff[0]] == b[diff[1]] and
                             a[diff[1]] == b[diff[0]])


def similar_groups(strs: List[str]) -> int:
    """Count groups of mutually similar strings."""
    n = len(strs)
    uf = UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if _similar(strs[i], strs[j]):
                uf.union(i, j)
    return uf.components

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
    assert similar_groups(["tars", "rats", "arts", "star"]) == 2
    assert similar_groups(["omv", "ovm"]) == 1
    assert similar_groups(["abc"]) == 1
    assert similar_groups(["ab", "ba", "ab"]) == 1
    assert stdlib_only()
    print("uf-35 OK")


if __name__ == "__main__":
    main()
