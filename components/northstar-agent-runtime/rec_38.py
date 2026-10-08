"""Edit distance: insert/delete/replace, memoised

Levenshtein recursion over both indices; O(m*n) with memo.

What this IS: a real memoised recursive edit distance.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_38_VERSION = "rec-edit-distance.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-edit-distance.v1"


class RecError(Exception):
    """Fail-closed."""


def edit(a: str, b: str) -> int:
    """Levenshtein distance between a and b."""
    memo = {}

    def rec(i, j) -> int:
        if i == len(a):
            return len(b) - j
        if j == len(b):
            return len(a) - i
        if (i, j) in memo:
            return memo[(i, j)]
        if a[i] == b[j]:
            r = rec(i + 1, j + 1)
        else:
            r = 1 + min(rec(i + 1, j), rec(i, j + 1), rec(i + 1, j + 1))
        memo[(i, j)] = r
        return r

    return rec(0, 0)

def test_edit_basic():
    assert edit("kitten", "sitting") == 3


def test_edit_empty():
    assert edit("", "abc") == 3


def test_edit_same():
    assert edit("abc", "abc") == 0


def test_edit_single():
    assert edit("a", "b") == 1

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_edit_basic()
    test_edit_empty()
    test_edit_same()
    test_edit_single()
    assert stdlib_only()
    print("rec-edit-distance OK")


if __name__ == "__main__":
    main()
