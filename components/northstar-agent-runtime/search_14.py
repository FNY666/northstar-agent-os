"""Rabin-Karp search, Simulated.

What this IS: rolling-hash substring search, O(n+m) average.

What this IS NOT: worst case O(nm); hash collisions need verify step.
"""

from __future__ import annotations

import ast


#: Module version.
SEARCH_14_VERSION = "search-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.search-14.v1"


class SearchError(Exception):
    """Fail-closed."""


def rabin_karp_search(text: str, pattern: str, base: int = 256, mod_: int = 101) -> int:
    """First index of pattern in text, or -1. Empty pattern -> 0."""
    if text is None or pattern is None:
        raise SearchError("args required")
    n, m = len(text), len(pattern)
    if m == 0:
        return 0
    if m > n:
        return -1
    h = pow(base, m - 1, mod_)
    ph = th = 0
    for i in range(m):
        ph = (ph * base + ord(pattern[i])) % mod_
        th = (th * base + ord(text[i])) % mod_
    for i in range(n - m + 1):
        if ph == th and text[i:i + m] == pattern:
            return i
        if i < n - m:
            th = (th - ord(text[i]) * h) * base + ord(text[i + m])
            th %= mod_
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
    assert rabin_karp_search("hello world", "world") == 6
    assert rabin_karp_search("aaaaa", "bba") == -1
    assert rabin_karp_search("abc", "") == 0
    assert stdlib_only()
    print("search-14.v1 OK")


if __name__ == "__main__":
    main()
