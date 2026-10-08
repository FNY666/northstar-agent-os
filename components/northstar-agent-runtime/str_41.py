"""Longest valid parentheses: stack of indices.

Tracks the last invalid index; best = max gap. O(n).

What this IS: a real O(n) implementation.
What this IS NOT: returning the substring itself.
"""

from __future__ import annotations

import ast

#: Module version.
STR_41_VERSION = "str-lvp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-valid-parentheses.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_valid_parentheses(s: str) -> int:
    """Length of the longest valid (well-formed) parentheses substring."""
    best = 0
    stack = [-1]
    for i, ch in enumerate(s):
        if ch == "(":
            stack.append(i)
        else:
            stack.pop()
            if not stack:
                stack.append(i)
            elif i - stack[-1] > best:
                best = i - stack[-1]
    return best


def test_lvp_basic():
    assert longest_valid_parentheses("(()") == 2


def test_lvp_mixed():
    assert longest_valid_parentheses(")()())") == 4


def test_lvp_empty():
    assert longest_valid_parentheses("") == 0


def test_lvp_all():
    assert longest_valid_parentheses("()()") == 4


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
    test_lvp_basic()
    test_lvp_mixed()
    test_lvp_empty()
    test_lvp_all()
    assert stdlib_only()
    print("str-41 OK: lvp")


if __name__ == "__main__":
    main()
