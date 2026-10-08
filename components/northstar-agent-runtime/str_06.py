"""Suffix array: sorted suffix index.

Naive O(n^2 log n) construction sorting all suffixes. The foundation for LCP, BWT-adjacent queries, and substring search.

What this IS: a correct naive construction.
What this IS NOT: SA-IS / induced sorting; that's the linear upgrade.
"""

from __future__ import annotations

import ast

#: Module version.
STR_06_VERSION = "str-suffix-array.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-suffix-array.v1"


class StrError(Exception):
    """Fail-closed."""


def suffix_array(s: str) -> list:
    """Return suffix array: starting indices of suffixes in sorted order."""
    return sorted(range(len(s)), key=lambda i: s[i:])


def suffix_array_search(s: str, sa: list, pattern: str) -> list:
    """Binary-search the suffix array for pattern occurrences."""
    lo, hi = 0, len(sa)
    while lo < hi:
        mid = (lo + hi) // 2
        if s[sa[mid]:sa[mid] + len(pattern)] < pattern:
            lo = mid + 1
        else:
            hi = mid
    res = []
    while lo < len(sa) and s[sa[lo]:sa[lo] + len(pattern)] == pattern:
        res.append(sa[lo])
        lo += 1
    return sorted(res)


def test_sa_banana():
    assert suffix_array("banana") == [5, 3, 1, 0, 4, 2]


def test_sa_empty():
    assert suffix_array("") == []


def test_sa_search():
    sa = suffix_array("banana")
    assert suffix_array_search("banana", sa, "ana") == [1, 3]


def test_sa_missing():
    sa = suffix_array("banana")
    assert suffix_array_search("banana", sa, "xyz") == []


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
    test_sa_banana()
    test_sa_empty()
    test_sa_search()
    test_sa_missing()
    assert stdlib_only()
    print("str-06 OK: suffix-array")


if __name__ == "__main__":
    main()
