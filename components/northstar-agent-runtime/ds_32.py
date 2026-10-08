"""DS: Union-Find (32/50). disjoint set union"""
from __future__ import annotations

import ast

#: Module version.
DS_32_VERSION = "ds-32-union-find.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-32.union-find.v1"


class UnionFind:
    """Disjoint-set union with path compression and union by rank."""

    def __init__(self, n):
        if n <= 0:
            raise ValueError("n must be positive")
        self._parent = list(range(n))
        self._rank = [0] * n

    def find(self, x):
        if not 0 <= x < len(self._parent):
            raise IndexError("out of range")
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a, b):
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return False
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1
        return True

    def connected(self, a, b):
        return self.find(a) == self.find(b)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    uf = UnionFind(5)
    assert uf.union(0, 1) is True
    assert uf.union(1, 2) is True
    assert uf.union(0, 2) is False
    assert uf.connected(0, 2) is True
    assert uf.connected(0, 3) is False
    assert stdlib_only()
    print("ds-32 OK: path compression, union by rank")


if __name__ == "__main__":
    main()
