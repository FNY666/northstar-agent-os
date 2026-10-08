"""Memoized Wildcard Matching: memoization example.

Wildcard match with '?' and '*': state (i, j) handles star by skipping or consuming. The (i, j) cache gives O(|s|*|p|).

What this IS: a real memoized wildcard matcher for '?' and '*'.
What this IS NOT: a regex matcher (see memo-47); the host picks the syntax.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_48_VERSION = "memo-wildcard-matching.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-wildcard-matching.v1"


class MemoError(Exception):
    """Fail-closed."""


def wildcard_match(s: str, p: str, i: int = 0, j: int = 0, _cache: dict | None = None) -> bool:
    """Memoized wildcard match supporting '?' and '*'."""
    cache: dict = _cache if _cache is not None else {}
    key = (i, j)
    if key in cache:
        return cache[key]
    if j == len(p):
        cache[key] = i == len(s)
    elif i == len(s):
        cache[key] = all(c == "*" for c in p[j:])
    elif p[j] == "*":
        cache[key] = wildcard_match(s, p, i, j + 1, cache) or wildcard_match(s, p, i + 1, j, cache)
    else:
        cache[key] = p[j] in (s[i], "?") and wildcard_match(s, p, i + 1, j + 1, cache)
    return cache[key]

def test_wildcard_match_example():
    assert wildcard_match("adceb", "*a*b") is True


def test_wildcard_match_question():
    assert wildcard_match("acdcb", "a*c?b") is False


def test_wildcard_match_star_only():
    assert wildcard_match("abc", "*") is True

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
    test_wildcard_match_example()
    test_wildcard_match_question()
    test_wildcard_match_star_only()
    assert stdlib_only()
    print("memo-48 OK: wildcard-matching")


if __name__ == "__main__":
    main()
