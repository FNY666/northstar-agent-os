"""Memoized Longest Valid Parentheses: memoization example.

Longest valid run via a memoized start_len(i): '()' adds 2 plus the tail, '(...)...'' chains nested and following runs. The wrapper takes the max over starts.

What this IS: a real memoized longest-valid-parentheses solver.
What this IS NOT: a stack-based linear scan; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_49_VERSION = "memo-longest-valid-parentheses.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-longest-valid-parentheses.v1"


class MemoError(Exception):
    """Fail-closed."""


def longest_valid(s: str, _cache: dict | None = None) -> int:
    """Memoized longest valid parentheses length."""
    cache: dict = _cache if _cache is not None else {}

    def start_len(i: int) -> int:
        if i in cache:
            return cache[i]
        if i + 1 >= len(s) or s[i] != "(":
            cache[i] = 0
        elif s[i + 1] == ")":
            cache[i] = 2 + start_len(i + 2)
        else:
            m = start_len(i + 1)
            if m > 0 and i + 1 + m < len(s) and s[i + 1 + m] == ")":
                cache[i] = 2 + m + start_len(i + 2 + m)
            else:
                cache[i] = 0
        return cache[i]

    return max((start_len(i) for i in range(len(s))), default=0)

def test_longest_valid_example():
    assert longest_valid(")()())") == 4


def test_longest_valid_nested():
    assert longest_valid("(()())") == 6


def test_longest_valid_none():
    assert longest_valid("(((") == 0

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
    test_longest_valid_example()
    test_longest_valid_nested()
    test_longest_valid_none()
    assert stdlib_only()
    print("memo-49 OK: longest-valid-parentheses")


if __name__ == "__main__":
    main()
