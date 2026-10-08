"""DS: Sparse Table (29/50). sparse table for RMQ"""
from __future__ import annotations

import ast

#: Module version.
DS_29_VERSION = "ds-29-sparse-table.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-29.sparse-table.v1"


class SparseTable:
    """Sparse table for O(1) range-minimum queries after O(n log n) build."""

    def __init__(self, data):
        if not data:
            raise ValueError("data must be non-empty")
        n = len(data)
        self._table = [list(data)]
        j = 1
        while (1 << j) <= n:
            prev = self._table[-1]
            half = 1 << (j - 1)
            size = n - (1 << j) + 1
            self._table.append(
                [prev[i] if prev[i] < prev[i + half] else prev[i + half]
                 for i in range(size)]
            )
            j += 1

    def query(self, left, right):
        """Minimum over [left, right)."""
        length = right - left
        if length <= 0:
            raise ValueError("empty range")
        j = length.bit_length() - 1
        row = self._table[j]
        a = row[left]
        b = row[right - (1 << j)]
        return a if a < b else b

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
    st = SparseTable([5, 2, 8, 1, 9, 3])
    assert st.query(0, 6) == 1
    assert st.query(0, 2) == 2
    assert st.query(2, 5) == 1
    assert st.query(4, 6) == 3
    assert stdlib_only()
    print("ds-29 OK: O(1) range-minimum queries")


if __name__ == "__main__":
    main()
