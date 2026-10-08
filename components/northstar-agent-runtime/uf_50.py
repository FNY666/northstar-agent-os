"""Mixed union-find query processor.

Drive a DSU with an operation stream: unions plus live queries for
component size and for the total component count. Answers are collected
in order.
"""
import ast
import sys
from typing import List, Tuple

UF_50_VERSION = "uf-50.v1"

class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.size = [1] * n
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
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        self.components -= 1
        return True

    def size_of(self, x: int) -> int:
        return self.size[self.find(x)]


def run_queries(n: int, ops: List[Tuple[str, int, int]]) -> List[int]:
    """Process ("union"|"size"|"count", a, b) ops; collect query answers."""
    uf = UnionFind(n)
    ans = []
    for op, a, b in ops:
        if op == "union":
            uf.union(a, b)
        elif op == "size":
            ans.append(uf.size_of(a))
        elif op == "count":
            ans.append(uf.components)
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
    ops = [("union", 0, 1), ("size", 0, 0), ("union", 2, 3),
           ("count", 0, 0), ("union", 1, 2), ("size", 3, 0)]
    assert run_queries(5, ops) == [2, 3, 4]
    assert run_queries(3, [("count", 0, 0)]) == [3]
    assert run_queries(2, [("union", 0, 1), ("union", 0, 1),
                          ("count", 0, 0)]) == [1]
    assert stdlib_only()
    print("uf-50 OK")


if __name__ == "__main__":
    main()
