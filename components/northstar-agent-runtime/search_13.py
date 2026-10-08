"""KMP substring search, Simulated.

What this IS: O(n+m) substring search via prefix function.

What this IS NOT: overkill for tiny patterns; use str.find there.
"""

from __future__ import annotations

import ast


#: Module version.
SEARCH_13_VERSION = "search-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-13.v1"


class SearchError(Exception):
    """Fail-closed."""


def _kmp_prefix(pattern: str):
    pi = [0] * len(pattern)
    for i in range(1, len(pattern)):
        j = pi[i - 1]
        while j > 0 and pattern[i] != pattern[j]:
            j = pi[j - 1]
        if pattern[i] == pattern[j]:
            j += 1
        pi[i] = j
    return pi


def kmp_search(text: str, pattern: str) -> int:
    """First index of pattern in text, or -1. Empty pattern -> 0."""
    if text is None or pattern is None:
        raise SearchError("args required")
    if pattern == "":
        return 0
    pi = _kmp_prefix(pattern)
    j = 0
    for i, ch in enumerate(text):
        while j > 0 and ch != pattern[j]:
            j = pi[j - 1]
        if ch == pattern[j]:
            j += 1
        if j == len(pattern):
            return i - j + 1
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
    assert kmp_search("ababcababc", "ababc") == 0
    assert kmp_search("hello world", "world") == 6
    assert kmp_search("abc", "d") == -1
    assert stdlib_only()
    print("search-13.v1 OK")


if __name__ == "__main__":
    main()
