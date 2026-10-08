"""DS: Top Tree (35/50). top tree (dynamic tree path queries)

Mock: cluster representation is stubbed; path queries run on an adjacency-list tree with BFS, so semantics are correct but not O(log n)."""
from __future__ import annotations

import ast

#: Module version.
DS_35_VERSION = "ds-35-top-tree.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-35.top-tree.v1"


class TopTree:
    """API-compatible top-tree stub (see module docstring)."""

    def __init__(self):
        self._adj = {}

    def _ensure(self, x):
        self._adj.setdefault(x, set())

    def link(self, a, b):
        self._ensure(a)
        self._ensure(b)
        self._adj[a].add(b)
        self._adj[b].add(a)

    def path(self, a, b):
        """Return the node list on the a-b path (BFS)."""
        if a == b:
            return [a]
        prev = {a: None}
        queue = [a]
        while queue:
            x = queue.pop(0)
            if x == b:
                break
            for y in self._adj.get(x, ()):
                if y not in prev:
                    prev[y] = x
                    queue.append(y)
        if b not in prev:
            raise ValueError("not connected")
        out = []
        cur = b
        while cur is not None:
            out.append(cur)
            cur = prev[cur]
        out.reverse()
        return out

    def path_length(self, a, b):
        return len(self.path(a, b)) - 1

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
    t = TopTree()
    t.link(1, 2); t.link(2, 3); t.link(2, 4)
    assert t.path(1, 3) == [1, 2, 3]
    assert t.path_length(1, 4) == 2
    assert t.path(2, 2) == [2]
    assert stdlib_only()
    print("ds-35 OK: tree path queries via BFS")


if __name__ == "__main__":
    main()
