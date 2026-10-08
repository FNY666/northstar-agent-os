"""Process restricted friend requests.

A request (p, q) is approved iff unioning p and q would not connect any
restricted pair. Check every restriction against the current DSU before
committing the union.
"""
import ast
import sys
from typing import List, Tuple

UF_36_VERSION = "uf-36.v1"

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

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)


def process_requests(n: int, restrictions: List[Tuple[int, int]],
                     requests: List[Tuple[int, int]]) -> List[bool]:
    """Approve each friend request unless it violates a restriction."""
    uf = UnionFind(n)
    ans = []
    for p, q in requests:
        ok = True
        for u, v in restrictions:
            if (uf.connected(u, p) and uf.connected(v, q)) or                (uf.connected(u, q) and uf.connected(v, p)):
                ok = False
                break
        if ok:
            uf.union(p, q)
        ans.append(ok)
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
    r = process_requests(3, [(0, 1)], [(0, 2), (2, 1)])
    assert r == [True, False]
    r2 = process_requests(5, [(0, 1), (1, 2), (2, 3)],
                          [(0, 4), (1, 2), (3, 1), (3, 4)])
    assert r2 == [True, False, True, False]
    assert process_requests(2, [], [(0, 1)]) == [True]
    assert stdlib_only()
    print("uf-36 OK")


if __name__ == "__main__":
    main()
