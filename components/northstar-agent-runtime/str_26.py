"""Mini regex engine: full-match with . * + ?.

Memoized recursive matcher supporting '.' (any), '*' (zero+), '+' (one+), '?' (zero/one) with full-match semantics.

What this IS: a real backtracking engine with memoization.
What this IS NOT: character classes, alternation, groups.
"""

from __future__ import annotations

import ast
from functools import lru_cache

#: Module version.
STR_26_VERSION = "str-mini-regex.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-mini-regex.v1"


class StrError(Exception):
    """Fail-closed."""


def regex_full_match(pattern: str, text: str) -> bool:
    """True iff pattern fully matches text. Ops: . * + ? (literals otherwise)."""

    @lru_cache(maxsize=None)
    def dp(pi: int, si: int) -> bool:
        if pi == len(pattern):
            return si == len(text)
        first = si < len(text) and pattern[pi] in (text[si], ".")
        if pi + 1 < len(pattern):
            q = pattern[pi + 1]
            if q == "*":
                return dp(pi + 2, si) or (first and dp(pi, si + 1))
            if q == "+":
                return first and (dp(pi + 2, si + 1) or dp(pi, si + 1))
            if q == "?":
                return dp(pi + 2, si) or (first and dp(pi + 2, si + 1))
        return first and dp(pi + 1, si + 1)

    return dp(0, 0)


def test_re_star():
    assert regex_full_match("a*b", "aaab") is True
    assert regex_full_match("a*b", "b") is True


def test_re_dot():
    assert regex_full_match("a.c", "abc") is True
    assert regex_full_match("a.c", "ac") is False


def test_re_plus():
    assert regex_full_match("a+c", "aaac") is True
    assert regex_full_match("a+c", "c") is False


def test_re_question():
    assert regex_full_match("colou?r", "color") is True
    assert regex_full_match("colou?r", "colour") is True


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "functools", "pathlib"}
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
    test_re_star()
    test_re_dot()
    test_re_plus()
    test_re_question()
    assert stdlib_only()
    print("str-26 OK: mini-regex")


if __name__ == "__main__":
    main()
