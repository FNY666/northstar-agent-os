"""Earliest moment when everyone becomes friends.

Sort friendship logs by timestamp and union incrementally; the first
timestamp at which a single component remains is the answer.
"""
import ast
import sys
from typing import List, Tuple

UF_39_VERSION = "uf-39.v1"

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


def earliest_moment(n: int, logs: List[Tuple[int, int, int]]) -> int:
    """Earliest timestamp when all n people are connected; -1 if never."""
    uf = UnionFind(n)
    for t, a, b in sorted(logs):
        uf.union(a, b)
        if uf.components == 1:
            return t
    return -1

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
    logs = [(20190101, 0, 1), (20190104, 3, 4), (20190107, 2, 3),
            (20190211, 1, 5), (20190224, 2, 4), (20190301, 0, 3),
            (20190312, 1, 2), (20190322, 4, 5)]
    assert earliest_moment(6, logs) == 20190301
    assert earliest_moment(3, [(1, 0, 1)]) == -1
    assert earliest_moment(2, [(5, 0, 1)]) == 5
    assert earliest_moment(1, []) == -1
    assert stdlib_only()
    print("uf-39 OK")


if __name__ == "__main__":
    main()
