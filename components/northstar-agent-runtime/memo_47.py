"""Memoized Regex Matching: memoization example.

Regex match with '.' and '*': state (i, j) handles star by skipping or consuming. The (i, j) cache gives O(|s|*|p|).

What this IS: a real memoized regex matcher for '.' and '*'.
What this IS NOT: a full regex engine; the host picks the feature set.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_47_VERSION = "memo-regex-matching.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-regex-matching.v1"


class MemoError(Exception):
    """Fail-closed."""


def regex_match(s: str, p: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> bool:
    """Memoized regex match supporting '.' and '*'."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if j == len(p):
        cache[key] = i == len(s)
    else:
        first = i < len(s) and p[j] in (s[i], ".")
        if j + 1 < len(p) and p[j + 1] == "*":
            cache[key] = regex_match(s, p, i, j + 2, cache) or (first and regex_match(s, p, i + 1, j, cache))
        else:
            cache[key] = first and regex_match(s, p, i + 1, j + 1, cache)
    return cache[key]

def test_regex_match_star():
    assert regex_match("aa", "a*") is True


def test_regex_match_dot_star():
    assert regex_match("ab", ".*") is True


def test_regex_match_complex():
    assert regex_match("aab", "c*a*b") is True

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
    test_regex_match_star()
    test_regex_match_dot_star()
    test_regex_match_complex()
    assert stdlib_only()
    print("memo-47 OK: regex-matching")


if __name__ == "__main__":
    main()
