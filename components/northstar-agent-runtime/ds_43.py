"""DS: BK-Tree (43/50). BK-tree for discrete metric spaces"""
from __future__ import annotations

import ast

#: Module version.
DS_43_VERSION = "ds-43-bk-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-43.bk-tree.v1"


def levenshtein(a, b):
    """Edit distance between strings ``a`` and ``b``."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class BKTree:
    """BK-tree for tolerance queries under a discrete metric."""

    def __init__(self, dist):
        self._dist = dist
        self._root = None

    def insert(self, item):
        if self._root is None:
            self._root = [item, {}]
            return
        node = self._root
        while True:
            d = self._dist(item, node[0])
            if d == 0:
                return
            child = node[1].get(d)
            if child is None:
                node[1][d] = [item, {}]
                return
            node = child

    def query(self, item, tolerance):
        """Return items within ``tolerance`` of ``item``."""
        out = []

        def rec(node):
            d = self._dist(item, node[0])
            if d <= tolerance:
                out.append(node[0])
            for cd, child in node[1].items():
                if abs(cd - d) <= tolerance:
                    rec(child)

        if self._root is not None:
            rec(self._root)
        return out

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
    t = BKTree(levenshtein)
    for w in ("book", "books", "cake", "boo"):
        t.insert(w)
    assert sorted(t.query("book", 1)) == ["boo", "book", "books"]
    assert t.query("cake", 0) == ["cake"]
    assert BKTree(levenshtein).query("x", 2) == []
    assert stdlib_only()
    print("ds-43 OK: tolerance queries under edit distance")


if __name__ == "__main__":
    main()
