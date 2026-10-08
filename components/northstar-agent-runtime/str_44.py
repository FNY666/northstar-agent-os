"""Reverse words: whitespace-normalized reversal.

Splits on whitespace runs, reverses word order, single-space joins.

What this IS: a real implementation.
What this IS NOT: in-place char-array reversal.
"""

from __future__ import annotations

import ast

#: Module version.
STR_44_VERSION = "str-reverse-words.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-reverse-words.v1"


class StrError(Exception):
    """Fail-closed."""


def reverse_words(s: str) -> str:
    """Reverse word order, collapsing whitespace."""
    return " ".join(reversed(s.split()))


def test_rw_basic():
    assert reverse_words("the sky is blue") == "blue is sky the"


def test_rw_spaces():
    assert reverse_words("  hello   world  ") == "world hello"


def test_rw_single():
    assert reverse_words("a") == "a"


def test_rw_empty():
    assert reverse_words("") == ""


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
    test_rw_basic()
    test_rw_spaces()
    test_rw_single()
    test_rw_empty()
    assert stdlib_only()
    print("str-44 OK: reverse-words")


if __name__ == "__main__":
    main()
