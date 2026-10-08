"""Weighted union-find: evaluate division.

Each node stores its ratio to its parent, so ``find`` both compresses the
path and accumulates the product of ratios. ``union(a, b, v)`` encodes
a / b = v; ``ratio(a, b)`` answers queries, -1.0 when disconnected.
"""
import ast
import sys
from typing import Dict, List, Tuple

UF_14_VERSION = "uf-14.v1"

class WeightedUF:
    """Union-find where each node tracks its value ratio to its parent."""

    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}
        self.weight: Dict[str, float] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
            self.weight[x] = 1.0
            return x
        if self.parent[x] != x:
            orig = self.parent[x]
            root = self.find(orig)
            self.weight[x] *= self.weight[orig]
            self.parent[x] = root
        return self.parent[x]

    def union(self, a: str, b: str, value: float) -> None:
        """Encode the equation a / b = value."""
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb
            self.weight[ra] = value * self.weight[b] / self.weight[a]

    def ratio(self, a: str, b: str) -> float:
        """Return a / b, or -1.0 when a and b are disconnected."""
        if a not in self.parent or b not in self.parent:
            return -1.0
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            return -1.0
        return self.weight[a] / self.weight[b]


def evaluate_division(equations: List[Tuple[str, str]], values: List[float],
                      queries: List[Tuple[str, str]]) -> List[float]:
    """Answer a/b queries from a list of division equations."""
    uf = WeightedUF()
    for (a, b), v in zip(equations, values):
        uf.union(a, b, v)
    return [uf.ratio(a, b) for a, b in queries]

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
    eq = [("a", "b"), ("b", "c")]
    q = evaluate_division(eq, [2.0, 3.0], [("a", "c"), ("b", "a"), ("a", "e")])
    assert abs(q[0] - 6.0) < 1e-9
    assert abs(q[1] - 0.5) < 1e-9
    assert q[2] == -1.0
    q2 = evaluate_division([("x", "x")], [1.0], [("x", "x")])
    assert abs(q2[0] - 1.0) < 1e-9
    q3 = evaluate_division([], [], [("a", "b")])
    assert q3 == [-1.0]
    assert stdlib_only()
    print("uf-14 OK")


if __name__ == "__main__":
    main()
