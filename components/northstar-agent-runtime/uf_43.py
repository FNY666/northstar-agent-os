"""Union-find with rollback.

Every union records the changed child, its new parent, and the parent's
previous size on a history stack. ``snapshot`` marks a point; ``rollback``
undoes all changes after it, enabling backtracking search over DSU state.
"""
import ast
import sys
from typing import List, Tuple

UF_43_VERSION = "uf-43.v1"

class RollbackUF:
    """DSU supporting undo of unions via an explicit change log."""

    def __init__(self, n: int) -> None:
        self.parent = list(range(n))
        self.size = [1] * n
        self.history: List[Tuple[int, int, int]] = []

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            self.history.append((-1, -1, -1))
            return False
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.history.append((rb, ra, self.size[ra]))
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]
        return True

    def snapshot(self) -> int:
        return len(self.history)

    def rollback(self, snap: int) -> None:
        while len(self.history) > snap:
            child, par, old_size = self.history.pop()
            if child == -1:
                continue
            self.parent[child] = child
            self.size[par] = old_size

    def connected(self, a: int, b: int) -> bool:
        return self.find(a) == self.find(b)

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
    uf = RollbackUF(4)
    s0 = uf.snapshot()
    uf.union(0, 1)
    s1 = uf.snapshot()
    uf.union(2, 3)
    uf.union(1, 2)
    assert uf.connected(0, 3)
    uf.rollback(s1)
    assert uf.connected(0, 1)
    assert not uf.connected(0, 2)
    uf.rollback(s0)
    assert not uf.connected(0, 1)
    assert uf.snapshot() == s0
    assert stdlib_only()
    print("uf-43 OK")


if __name__ == "__main__":
    main()
