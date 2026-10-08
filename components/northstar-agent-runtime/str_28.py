"""Prefix function + minimal period: KMP pi table standalone.

pi[i] = longest proper border of s[:i+1]; minimal period from n - pi[n-1].

What this IS: a real O(n) prefix function.
What this IS NOT: border chain enumeration.
"""

from __future__ import annotations

import ast

#: Module version.
STR_28_VERSION = "str-prefix-fn.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-prefix-function.v1"


class StrError(Exception):
    """Fail-closed."""


def prefix_function(s: str) -> list:
    """KMP prefix function."""
    pi = [0] * len(s)
    for i in range(1, len(s)):
        j = pi[i - 1]
        while j > 0 and s[i] != s[j]:
            j = pi[j - 1]
        if s[i] == s[j]:
            j += 1
        pi[i] = j
    return pi


def minimal_period(s: str) -> int:
    """Smallest p with s = t repeated (p == len(s) if none)."""
    if not s:
        return 0
    n = len(s)
    p = n - prefix_function(s)[-1]
    return p if n % p == 0 else n


def test_pi_known():
    assert prefix_function("aabaaab") == [0, 1, 0, 1, 2, 2, 3]


def test_period_repeat():
    assert minimal_period("abcabc") == 3


def test_period_none():
    assert minimal_period("abcd") == 4


def test_period_empty():
    assert minimal_period("") == 0


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
    test_pi_known()
    test_period_repeat()
    test_period_none()
    test_period_empty()
    assert stdlib_only()
    print("str-28 OK: prefix-function")


if __name__ == "__main__":
    main()
