"""Manacher's algorithm: linear-time longest palindromic substring.

Finds the longest palindromic substring in O(n) by expanding around centers on a transformed string with sentinels, reusing mirror radii.

What this IS: a real O(n) implementation.
What this IS NOT: palindromic tree / Eertree; that's a separate structure.
"""

from __future__ import annotations

import ast

#: Module version.
STR_05_VERSION = "str-manacher.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-manacher.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_palindromic_substring(s: str) -> str:
    """Return one longest palindromic substring of s."""
    if not s:
        return ""
    t = "^#" + "#".join(s) + "#$"
    n = len(t)
    p = [0] * n
    c = r = 0
    for i in range(1, n - 1):
        mirror = 2 * c - i
        if i < r:
            p[i] = min(r - i, p[mirror])
        while t[i + 1 + p[i]] == t[i - 1 - p[i]]:
            p[i] += 1
        if i + p[i] > r:
            c, r = i, i + p[i]
    max_len = max(p)
    center = p.index(max_len)
    start = (center - max_len) // 2
    return s[start:start + max_len]


def test_manacher_odd():
    assert longest_palindromic_substring("babad") in ("bab", "aba")


def test_manacher_even():
    assert longest_palindromic_substring("cbbd") == "bb"


def test_manacher_empty():
    assert longest_palindromic_substring("") == ""


def test_manacher_single():
    assert longest_palindromic_substring("a") == "a"


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
    test_manacher_odd()
    test_manacher_even()
    test_manacher_empty()
    test_manacher_single()
    assert stdlib_only()
    print("str-05 OK: manacher")


if __name__ == "__main__":
    main()
