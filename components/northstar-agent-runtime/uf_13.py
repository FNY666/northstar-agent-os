"""Lexicographically smallest equivalent string.

Union characters that must be equivalent, then map every character of the
base string to the smallest character in its component.
"""
import ast
import sys

UF_13_VERSION = "uf-13.v1"

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


def smallest_equivalent(s1: str, s2: str, base: str) -> str:
    """Map each char of ``base`` to its component's smallest char."""
    uf = UnionFind(26)
    for a, b in zip(s1, s2):
        uf.union(ord(a) - 97, ord(b) - 97)
    best = {}
    for i in range(26):
        root = uf.find(i)
        ch = chr(i + 97)
        if root not in best or ch < best[root]:
            best[root] = ch
    return "".join(best[uf.find(ord(c) - 97)] for c in base)

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
    assert smallest_equivalent("parker", "morris", "parser") == "makkek"
    assert smallest_equivalent("hello", "world", "hold") == "hdld"
    assert smallest_equivalent("a", "b", "c") == "c"
    assert smallest_equivalent("ab", "ba", "ab") == "aa"
    assert stdlib_only()
    print("uf-13 OK")


if __name__ == "__main__":
    main()
