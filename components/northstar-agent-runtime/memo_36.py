"""Memoized Scramble String: memoization example.

Is s2 a scramble of s1? Try every split point both straight and swapped. The (s1, s2) cache with a sorted-multiset prune keeps small inputs fast.

What this IS: a real memoized scramble checker with a character-multiset prune.
What this IS NOT: a scramble enumerator; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_36_VERSION = "memo-scramble-string.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-scramble-string.v1"


class MemoError(Exception):
    """Fail-closed."""


def is_scramble(s1: str, s2: str, _cache: dict | None = None) -> bool:
    """Memoized scramble-string check."""
    cache: dict = _cache if _cache is not None else {}
    key = (s1, s2)
    if key in cache:
        return cache[key]
    if s1 == s2:
        cache[key] = True
    elif sorted(s1) != sorted(s2):
        cache[key] = False
    else:
        n = len(s1)
        ok = False
        for i in range(1, n):
            if (is_scramble(s1[:i], s2[:i], cache) and is_scramble(s1[i:], s2[i:], cache)) or (
                is_scramble(s1[:i], s2[n - i:], cache) and is_scramble(s1[i:], s2[:n - i], cache)
            ):
                ok = True
                break
        cache[key] = ok
    return cache[key]

def test_is_scramble_true():
    assert is_scramble("great", "rgeat") is True


def test_is_scramble_false():
    assert is_scramble("abcde", "caebd") is False


def test_is_scramble_same():
    assert is_scramble("abc", "abc") is True

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
    test_is_scramble_true()
    test_is_scramble_false()
    test_is_scramble_same()
    assert stdlib_only()
    print("memo-36 OK: scramble-string")


if __name__ == "__main__":
    main()
