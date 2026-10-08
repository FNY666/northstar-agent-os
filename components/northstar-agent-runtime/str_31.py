"""Longest repeated substring: suffix array + adjacent LCP.

Builds the naive suffix array, then takes the max LCP over adjacent pairs.

What this IS: a real LRS implementation.
What this IS NOT: linear-time via SA-IS + Kasai.
"""

from __future__ import annotations

import ast

#: Module version.
STR_31_VERSION = "str-lrs.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-repeated-substring.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_repeated_substring(s: str) -> str:
    """Return one longest substring occurring at least twice ('' if none)."""
    n = len(s)
    if n < 2:
        return ""
    sa = sorted(range(n), key=lambda i: s[i:])
    best = ""
    for k in range(1, n):
        i, j = sa[k - 1], sa[k]
        h = 0
        while i + h < n and j + h < n and s[i + h] == s[j + h]:
            h += 1
        if h > len(best):
            best = s[i:i + h]
    return best


def test_lrs_banana():
    assert longest_repeated_substring("banana") == "ana"


def test_lrs_none():
    assert longest_repeated_substring("abcd") == ""


def test_lrs_all_same():
    assert longest_repeated_substring("aaaa") == "aaa"


def test_lrs_short():
    assert longest_repeated_substring("a") == ""


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
    test_lrs_banana()
    test_lrs_none()
    test_lrs_all_same()
    test_lrs_short()
    assert stdlib_only()
    print("str-31 OK: lrs")


if __name__ == "__main__":
    main()
