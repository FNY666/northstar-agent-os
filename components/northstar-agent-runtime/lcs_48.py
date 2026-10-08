"""LCS row generator

What this IS: lazily yields DP rows one at a time for streaming/inspection use.

What this IS NOT:
* the full table -- see lcs_30.
* online LCS -- see lcs_35.
"""

from __future__ import annotations

import ast
from typing import Iterator, List
#: Module version.
LCS_48_VERSION = "lcs-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-48.v1"


def lcs_rows(a: str, b: str) -> Iterator[List[int]]:
    # Yield row 0, then one row per character of a.
    prev = [0] * (len(b) + 1)
    yield list(prev)
    for ca in a:
        cur = [0] * (len(b) + 1)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        yield list(cur)
        prev = cur

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "typing"}
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
    rows = list(lcs_rows("abcde", "ace"))
    assert len(rows) == 6 and rows[-1][-1] == 3
    assert rows[0] == [0, 0, 0, 0]
    assert all(len(r) == 4 for r in rows)
    rows = list(lcs_rows("", "abc"))
    assert rows == [[0, 0, 0, 0]]
    rows = list(lcs_rows("a", ""))
    assert rows[-1] == [0]
    assert stdlib_only()
    print("48-ok OK")


if __name__ == "__main__":
    main()
