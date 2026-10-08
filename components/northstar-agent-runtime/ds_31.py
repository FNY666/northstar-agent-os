"""DS: Mo's Algorithm (31/50). Mo's offline range queries

Mock: the sqrt-decomposition query reordering is stubbed; queries are answered naively in insertion order, so the API is correct but without Mo's complexity benefit."""
from __future__ import annotations

import ast

#: Module version.
DS_31_VERSION = "ds-31-mos.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-31.mos.v1"


class MoSolver:
    """API-compatible Mo's-algorithm stub (see module docstring)."""

    def __init__(self):
        self._queries = []

    def add_query(self, left, right):
        if not 0 <= left <= right:
            raise ValueError("bad range")
        self._queries.append((left, right))
        return len(self._queries) - 1

    def solve(self, arr, fn):
        """Answer each query by applying ``fn`` to arr[left:right]."""
        return [fn(arr[left:right]) for (left, right) in self._queries]

    def query_count(self):
        return len(self._queries)

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
    mo = MoSolver()
    mo.add_query(0, 3); mo.add_query(1, 4)
    assert mo.solve([1, 2, 3, 4], sum) == [6, 9]
    assert mo.query_count() == 2
    assert stdlib_only()
    print("ds-31 OK: offline queries, naive backend")


if __name__ == "__main__":
    main()
