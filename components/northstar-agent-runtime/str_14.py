"""Anagram check: Counter-based permutation test.

Two strings are anagrams iff their character multisets match.

What this IS: a real O(n) check.
What this IS NOT: unicode normalization; normalize before calling.
"""

from __future__ import annotations

import ast
from collections import Counter

#: Module version.
STR_14_VERSION = "str-anagram.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-anagram-check.v1"


class StrError(Exception):
    """Fail-closed."""


def is_anagram(a: str, b: str) -> bool:
    """True iff a is a permutation of b."""
    return Counter(a) == Counter(b)


def anagram_signature(s: str) -> tuple:
    """Canonical key for grouping anagrams."""
    return tuple(sorted(Counter(s).items()))


def test_anagram_true():
    assert is_anagram("listen", "silent") is True


def test_anagram_false():
    assert is_anagram("hello", "world") is False


def test_anagram_length():
    assert is_anagram("a", "aa") is False


def test_anagram_sig():
    assert anagram_signature("abc") == anagram_signature("cba")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "collections", "pathlib"}
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
    test_anagram_true()
    test_anagram_false()
    test_anagram_length()
    test_anagram_sig()
    assert stdlib_only()
    print("str-14 OK: anagram")


if __name__ == "__main__":
    main()
