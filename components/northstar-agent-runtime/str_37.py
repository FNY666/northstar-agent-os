"""Minimum window substring: sliding window with need counts.

Expands right, contracts left while all of t is covered; O(n).

What this IS: a real O(n) implementation.
What this IS NOT: lexicographically smallest among minima.
"""

from __future__ import annotations

import ast
from collections import Counter

#: Module version.
STR_37_VERSION = "str-min-window.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-minimum-window-substring.v1"


class StrError(Exception):
    """Fail-closed."""


def min_window(s: str, t: str) -> str:
    """Smallest window of s containing all chars of t ('' if none)."""
    if not t or not s:
        return ""
    need = Counter(t)
    missing = len(t)
    left = 0
    best = ""
    for right, ch in enumerate(s):
        if need[ch] > 0:
            missing -= 1
        need[ch] -= 1
        while missing == 0:
            win = s[left:right + 1]
            if not best or len(win) < len(best):
                best = win
            need[s[left]] += 1
            if need[s[left]] > 0:
                missing += 1
            left += 1
    return best


def test_mw_classic():
    assert min_window("ADOBECODEBANC", "ABC") == "BANC"


def test_mw_single():
    assert min_window("a", "a") == "a"


def test_mw_none():
    assert min_window("a", "aa") == ""


def test_mw_empty():
    assert min_window("", "a") == ""


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "collections", "pathlib"}
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
    test_mw_classic()
    test_mw_single()
    test_mw_none()
    test_mw_empty()
    assert stdlib_only()
    print("str-37 OK: min-window")


if __name__ == "__main__":
    main()
