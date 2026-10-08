"""Memoized Edit Distance: memoization example.

Levenshtein distance over (i, j): match costs 0, else 1 + min(insert, delete, replace). The cache gives O(|a|*|b|).

What this IS: a real memoized edit distance, fail-closed on nothing but honest about non-string input.
What this IS NOT: a Damerau transposition variant; the host picks the distance.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_07_VERSION = "memo-edit-distance.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-edit-distance.v1"


class MemoError(Exception):
    """Fail-closed."""


def edit_distance(a: str, b: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> int:
    """Memoized Levenshtein distance."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if i == len(a):
        cache[key] = len(b) - j
    elif j == len(b):
        cache[key] = len(a) - i
    elif a[i] == b[j]:
        cache[key] = edit_distance(a, b, i + 1, j + 1, cache)
    else:
        cache[key] = 1 + min(
            edit_distance(a, b, i + 1, j, cache),
            edit_distance(a, b, i, j + 1, cache),
            edit_distance(a, b, i + 1, j + 1, cache),
        )
    return cache[key]

def test_edit_distance_example():
    assert edit_distance("horse", "ros") == 3


def test_edit_distance_empty():
    assert edit_distance("", "abc") == 3


def test_edit_distance_same():
    assert edit_distance("same", "same") == 0

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
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
    test_edit_distance_example()
    test_edit_distance_empty()
    test_edit_distance_same()
    assert stdlib_only()
    print("memo-07 OK: edit-distance")


if __name__ == "__main__":
    main()
