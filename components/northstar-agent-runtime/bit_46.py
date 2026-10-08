"""Find the difference: extra char via XOR of code points.

XORing both strings cancels every shared character, leaving the added one.

What this IS: the checksum-style difference finder.
What this IS NOT: a diff; it assumes exactly one extra char.
"""

from __future__ import annotations

import ast

#: Module version.
BIT_46_VERSION = "bit-find-the-difference.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bit-find-the-difference.v1"


class BitError(Exception):
    """Fail-closed."""


def find_the_difference(s: str, t: str) -> str:
    """t = s + one extra char; find it via XOR."""
    if len(t) != len(s) + 1:
        raise BitError("t must be s plus one char")
    x = 0
    for c in s:
        x ^= ord(c)
    for c in t:
        x ^= ord(c)
    return chr(x)

def test_diff_basic():
    assert find_the_difference("abcd", "abcde") == "e"


def test_diff_empty():
    assert find_the_difference("", "y") == "y"


def test_diff_dup():
    assert find_the_difference("a", "aa") == "a"


def test_diff_bad_raises():
    try:
        find_the_difference("ab", "ab")
    except BitError:
        return
    raise AssertionError("expected BitError")

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
    test_diff_basic()
    test_diff_empty()
    test_diff_dup()
    test_diff_bad_raises()
    assert stdlib_only()
    print("bit-46 OK: find-the-difference")


if __name__ == "__main__":
    main()
