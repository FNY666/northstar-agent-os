"""Wildcard matching: linear greedy ? and * matcher.

Greedy two-pointer with backtracking on the last star; O(n*m) worst case, O(1) space.

What this IS: a real greedy matcher.
What this IS NOT: character classes; use str-26 mini-regex.
"""

from __future__ import annotations

import ast

#: Module version.
STR_13_VERSION = "str-wildcard.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-wildcard-matching.v1"


class StrError(Exception):
    """Fail-closed."""


def wildcard_match(s: str, p: str) -> bool:
    """Full match of s against pattern p with '?' (one char) and '*' (any run)."""
    si = pi = 0
    star = -1
    match = 0
    while si < len(s):
        if pi < len(p) and p[pi] in (s[si], "?"):
            si += 1
            pi += 1
        elif pi < len(p) and p[pi] == "*":
            star = pi
            pi += 1
            match = si
        elif star != -1:
            pi = star + 1
            match += 1
            si = match
        else:
            return False
    while pi < len(p) and p[pi] == "*":
        pi += 1
    return pi == len(p)


def test_wc_star():
    assert wildcard_match("aa", "a*") is True
    assert wildcard_match("ab", "?*") is True


def test_wc_fail():
    assert wildcard_match("aab", "c*a*b") is False


def test_wc_empty():
    assert wildcard_match("", "*") is True
    assert wildcard_match("", "?") is False


def test_wc_exact():
    assert wildcard_match("abc", "abc") is True


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
    test_wc_star()
    test_wc_fail()
    test_wc_empty()
    test_wc_exact()
    assert stdlib_only()
    print("str-13 OK: wildcard")


if __name__ == "__main__":
    main()
