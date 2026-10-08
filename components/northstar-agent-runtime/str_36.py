"""Longest substring without repeating chars: sliding window + last index.

Moves the left edge past the previous occurrence; O(n).

What this IS: a real O(n) implementation.
What this IS NOT: returning the substring itself.
"""

from __future__ import annotations

import ast

#: Module version.
STR_36_VERSION = "str-unique-substr.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-unique-substring.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_unique_substring(s: str) -> int:
    """Length of the longest substring with all distinct characters."""
    last = {}
    left = 0
    best = 0
    for right, ch in enumerate(s):
        if ch in last and last[ch] >= left:
            left = last[ch] + 1
        last[ch] = right
        if right - left + 1 > best:
            best = right - left + 1
    return best


def test_lus_classic():
    assert longest_unique_substring("abcabcbb") == 3


def test_lus_repeat():
    assert longest_unique_substring("bbbbb") == 1


def test_lus_empty():
    assert longest_unique_substring("") == 0


def test_lus_mixed():
    assert longest_unique_substring("pwwkew") == 3


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
    test_lus_classic()
    test_lus_repeat()
    test_lus_empty()
    test_lus_mixed()
    assert stdlib_only()
    print("str-36 OK: unique-substr")


if __name__ == "__main__":
    main()
