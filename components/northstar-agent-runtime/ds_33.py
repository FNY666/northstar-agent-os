"""DS: Link-Cut Tree (33/50). link-cut tree (dynamic forest)

Mock: splay-based path representation is stubbed; the dynamic-forest API (link/cut/connected) is backed by an adjacency list with BFS, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast

#: Module version.
DS_33_VERSION = "ds-33-lct.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-33.lct.v1"


class LinkCutTree:
    """API-compatible link-cut-tree stub (see module docstring)."""

    def __init__(self):
        self._adj = {}

    def _ensure(self, x):
        self._adj.setdefault(x, set())

    def link(self, a, b):
        self._ensure(a)
        self._ensure(b)
        if self.connected(a, b):
            raise ValueError("already connected (would create cycle)")
        self._adj[a].add(b)
        self._adj[b].add(a)

    def cut(self, a, b):
        self._adj.get(a, set()).discard(b)
        self._adj.get(b, set()).discard(a)

    def connected(self, a, b):
        if a == b:
            return True
        seen = {a}
        stack = [a]
        while stack:
            x = stack.pop()
            for y in self._adj.get(x, ()):
                if y == b:
                    return True
                if y not in seen:
                    seen.add(y)
                    stack.append(y)
        return False

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
    t = LinkCutTree()
    t.link(1, 2); t.link(2, 3)
    assert t.connected(1, 3) is True
    assert t.connected(1, 4) is False
    t.cut(2, 3)
    assert t.connected(1, 3) is False
    assert stdlib_only()
    print("ds-33 OK: dynamic forest link/cut/connected")


if __name__ == "__main__":
    main()
