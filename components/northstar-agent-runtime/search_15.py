"""Horspool search, Simulated.

What this IS: simplified Boyer-Moore with bad-character shifts.

What this IS NOT: not the full Boyer-Moore (no good-suffix rule).
"""

from __future__ import annotations

import ast


#: Module version.
SEARCH_15_VERSION = "search-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-15.v1"


class SearchError(Exception):
    """Fail-closed."""


def horspool_search(text: str, pattern: str) -> int:
    """First index of pattern in text, or -1. Empty pattern -> 0."""
    if text is None or pattern is None:
        raise SearchError("args required")
    n, m = len(text), len(pattern)
    if m == 0:
        return 0
    if m > n:
        return -1
    shift = {c: m - 1 - i for i, c in enumerate(pattern[:-1])}
    i = m - 1
    while i < n:
        k = 0
        while k < m and pattern[m - 1 - k] == text[i - k]:
            k += 1
        if k == m:
            return i - m + 1
        i += shift.get(text[i], m)
    return -1

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "heapq",
               "itertools", "math", "pathlib", "random", "typing"}
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
    assert horspool_search("hello world", "world") == 6
    assert horspool_search("abc", "d") == -1
    assert horspool_search("abc", "") == 0
    assert stdlib_only()
    print("search-15.v1 OK")


if __name__ == "__main__":
    main()
