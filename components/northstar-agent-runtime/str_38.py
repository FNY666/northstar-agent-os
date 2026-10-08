"""Valid parentheses: stack validator.

Pushes openers, pops on closers; O(n).

What this IS: a real O(n) validator.
What this IS NOT: wildcard-parentheses variants.
"""

from __future__ import annotations

import ast

#: Module version.
STR_38_VERSION = "str-valid-parens.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-valid-parentheses.v1"


class StrError(Exception):
    """Fail-closed."""


def is_valid_parentheses(s: str) -> bool:
    """True iff brackets are correctly nested."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for ch in s:
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack


def test_vp_true():
    assert is_valid_parentheses("()[]{}") is True
    assert is_valid_parentheses("{[()]}") is True


def test_vp_false():
    assert is_valid_parentheses("(]") is False
    assert is_valid_parentheses("([)]") is False


def test_vp_empty():
    assert is_valid_parentheses("") is True


def test_vp_unclosed():
    assert is_valid_parentheses("(()") is False


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
    test_vp_true()
    test_vp_false()
    test_vp_empty()
    test_vp_unclosed()
    assert stdlib_only()
    print("str-38 OK: valid-parens")


if __name__ == "__main__":
    main()
