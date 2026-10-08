"""Knuth-Morris-Pratt search: linear-time substring search.

Finds all occurrences of a pattern in text in O(n+m) using the LPS (longest proper prefix which is also suffix) table to skip re-scans.

What this IS: a real O(n+m) implementation with the prefix function.
What this IS NOT: a replacement for Python's find(); the host picks the matcher.
"""

from __future__ import annotations

import ast

#: Module version.
STR_01_VERSION = "str-kmp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-kmp.v1"


class StrError(Exception):
    """Fail-closed."""


def compute_lps(pattern: str) -> list:
    """LPS table: lps[i] = longest proper prefix of pattern[:i+1] that is also a suffix."""
    lps = [0] * len(pattern)
    length = 0
    i = 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        elif length != 0:
            length = lps[length - 1]
        else:
            lps[i] = 0
            i += 1
    return lps


def kmp_search(text: str, pattern: str) -> list:
    """Return start indices of all occurrences of pattern in text."""
    if not pattern:
        return []
    lps = compute_lps(pattern)
    res = []
    i = j = 0
    while i < len(text):
        if text[i] == pattern[j]:
            i += 1
            j += 1
        if j == len(pattern):
            res.append(i - j)
            j = lps[j - 1]
        elif i < len(text) and text[i] != pattern[j]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1
    return res


def test_kmp_basic():
    assert kmp_search("ABABDABACDABABCABAB", "ABABCABAB") == [10]


def test_kmp_overlap():
    assert kmp_search("AAAAA", "AA") == [0, 1, 2, 3]


def test_kmp_none():
    assert kmp_search("hello", "world") == []


def test_kmp_empty_pattern():
    assert kmp_search("abc", "") == []


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
    test_kmp_basic()
    test_kmp_overlap()
    test_kmp_none()
    test_kmp_empty_pattern()
    assert stdlib_only()
    print("str-01 OK: kmp")


if __name__ == "__main__":
    main()
