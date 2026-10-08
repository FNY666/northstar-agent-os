"""Number of good paths.

A path is good when its endpoints share the same value and every node on
it is <= that value. Process values increasingly; after unioning each
value group with already-active (smaller-or-equal) neighbours, count
connected pairs inside the group.
"""
import ast
import sys
from typing import Dict, List

UF_25_VERSION = "uf-25.v1"

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


def good_paths(vals: List[int], edges: List[List[int]]) -> int:
    """Count good paths in a tree with node values."""
    n = len(vals)
    adj: Dict[int, List[int]] = {i: [] for i in range(n)}
    for a, b in edges:
        adj[a].append(b)
        adj[b].append(a)
    by_val: Dict[int, List[int]] = {}
    for i, v in enumerate(vals):
        by_val.setdefault(v, []).append(i)
    uf = UnionFind(n)
    ans = 0
    for v in sorted(by_val):
        for u in by_val[v]:
            for w in adj[u]:
                if vals[w] <= v:
                    uf.union(u, w)
        cnt: Dict[int, int] = {}
        for u in by_val[v]:
            r = uf.find(u)
            cnt[r] = cnt.get(r, 0) + 1
        for c in cnt.values():
            ans += c * (c + 1) // 2
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
    assert good_paths([1, 3, 2, 1, 3], [[0, 1], [0, 2], [2, 3], [2, 4]]) == 6
    assert good_paths([1, 1, 2, 2, 3], [[0, 1], [1, 2], [2, 3], [2, 4]]) == 7
    assert good_paths([1], []) == 1
    assert good_paths([2, 2], [[0, 1]]) == 3
    assert stdlib_only()
    print("uf-25 OK")


if __name__ == "__main__":
    main()
