"""LCP array (Kasai): linear longest-common-prefix of adjacent suffixes.

Kasai's O(n) algorithm: lcp[i] = LCP of suffixes sa[i], sa[i+1] using the rank array and the h-1 trick.

What this IS: a real O(n) Kasai implementation.
What this IS NOT: a suffix-array builder; pass sa in.
"""

from __future__ import annotations

import ast

#: Module version.
STR_07_VERSION = "str-lcp-array.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-lcp-array.v1"


class StrError(Exception):
    """Fail-closed."""


def lcp_array(s: str, sa: list) -> list:
    """Kasai: lcp[i] = lcp(suffix sa[i], suffix sa[i+1])."""
    n = len(s)
    if n <= 1:
        return []
    rank = [0] * n
    for i, pos in enumerate(sa):
        rank[pos] = i
    lcp = [0] * (n - 1)
    h = 0
    for i in range(n):
        if rank[i] == 0:
            continue
        j = sa[rank[i] - 1]
        while i + h < n and j + h < n and s[i + h] == s[j + h]:
            h += 1
        lcp[rank[i] - 1] = h
        if h:
            h -= 1
    return lcp


def test_lcp_banana():
    assert lcp_array("banana", [5, 3, 1, 0, 4, 2]) == [1, 3, 0, 0, 2]


def test_lcp_aaaa():
    assert lcp_array("aaaa", [3, 2, 1, 0]) == [1, 2, 3]


def test_lcp_empty():
    assert lcp_array("", []) == []


def test_lcp_single():
    assert lcp_array("a", [0]) == []


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
    test_lcp_banana()
    test_lcp_aaaa()
    test_lcp_empty()
    test_lcp_single()
    assert stdlib_only()
    print("str-07 OK: lcp-array")


if __name__ == "__main__":
    main()
