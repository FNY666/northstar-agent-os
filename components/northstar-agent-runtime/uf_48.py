"""Possible bipartition via union-find with parity.

Model "must be in different groups" with a DSU that stores each node's
xor-distance (parity) to its root. Unioning a dislike pair forces opposite
parities; a contradiction means no bipartition exists.
"""
import ast
import sys
from typing import List, Tuple

UF_48_VERSION = "uf-48.v1"

class ParityUF:
    """DSU tracking xor parity from each node to its root."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.diff = [0] * n

    def find(self, x: int) -> Tuple[int, int]:
        if self.parent[x] != x:
            root, parity = self.find(self.parent[x])
            self.diff[x] ^= parity
            self.parent[x] = root
        return self.parent[x], self.diff[x]

    def separate(self, a: int, b: int) -> bool:
        """Force a and b into different groups; False on contradiction."""
        ra, pa = self.find(a)
        rb, pb = self.find(b)
        if ra == rb:
            return pa != pb
        self.parent[ra] = rb
        self.diff[ra] = pa ^ pb ^ 1
        return True


def possible_bipartition(n: int, dislikes: List[Tuple[int, int]]) -> bool:
    """True iff people 1..n split into two groups with no dislike inside."""
    uf = ParityUF(n + 1)
    for a, b in dislikes:
        if not uf.separate(a, b):
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
    assert possible_bipartition(4, [(1, 2), (1, 3), (2, 4)]) is True
    assert possible_bipartition(3, [(1, 2), (1, 3), (2, 3)]) is False
    assert possible_bipartition(5, [(1, 2), (2, 3), (3, 4), (4, 5), (1, 5)]) is False
    assert possible_bipartition(5, [(1, 2), (3, 4)]) is True
    assert stdlib_only()
    print("uf-48 OK")


if __name__ == "__main__":
    main()
