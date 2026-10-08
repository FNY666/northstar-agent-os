"""Satisfiability of equality equations.

Union all variables linked by "==", then verify that no "!=" equation
connects two variables in the same component.
"""
import ast
import sys
from typing import List

UF_18_VERSION = "uf-18.v1"

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


def equations_possible(equations: List[str]) -> bool:
    """True iff the == / != equations over a-z are simultaneously satisfiable."""
    uf = UnionFind(26)
    for e in equations:
        if e[1:3] == "==":
            uf.union(ord(e[0]) - 97, ord(e[3]) - 97)
    for e in equations:
        if e[1:3] == "!=":
            if uf.find(ord(e[0]) - 97) == uf.find(ord(e[3]) - 97):
                return False
    return True

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
    assert equations_possible(["a==b", "b!=a"]) is False
    assert equations_possible(["a==b", "b==c", "a==c"]) is True
    assert equations_possible(["a==b", "b!=c", "c==a"]) is False
    assert equations_possible(["c==c", "b==d", "x!=z"]) is True
    assert stdlib_only()
    print("uf-18 OK")


if __name__ == "__main__":
    main()
