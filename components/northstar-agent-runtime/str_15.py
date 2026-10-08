"""Palindrome check: two-pointer O(1) space test.

Compares s[i] with s[n-1-i] directly.

What this IS: a real O(n) time / O(1) space check.
What this IS NOT: alphanumeric-only mode; filter before calling.
"""

from __future__ import annotations

import ast

#: Module version.
STR_15_VERSION = "str-palindrome.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-palindrome-check.v1"


class StrError(Exception):
    """Fail-closed."""


def is_palindrome(s: str) -> bool:
    """True iff s reads the same forward and backward."""
    i, j = 0, len(s) - 1
    while i < j:
        if s[i] != s[j]:
            return False
        i += 1
        j -= 1
    return True


def test_pal_true():
    assert is_palindrome("racecar") is True
    assert is_palindrome("abba") is True


def test_pal_false():
    assert is_palindrome("hello") is False


def test_pal_empty():
    assert is_palindrome("") is True


def test_pal_single():
    assert is_palindrome("x") is True


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
    test_pal_true()
    test_pal_false()
    test_pal_empty()
    test_pal_single()
    assert stdlib_only()
    print("str-15 OK: palindrome")


if __name__ == "__main__":
    main()
