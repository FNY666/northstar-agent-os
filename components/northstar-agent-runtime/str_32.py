"""Longest substring with <= K distinct chars: sliding window.

Two-pointer window with a frequency map; O(n).

What this IS: a real O(n) sliding window.
What this IS NOT: exactly-K variant (inclusion-exclusion on top).
"""

from __future__ import annotations

import ast
from collections import defaultdict

#: Module version.
STR_32_VERSION = "str-k-distinct.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-longest-k-distinct.v1"


class StrError(Exception):
    """Fail-closed."""


def longest_k_distinct(s: str, k: int) -> str:
    """Return one longest substring containing at most k distinct characters."""
    if k <= 0 or not s:
        return ""
    cnt = defaultdict(int)
    left = 0
    best = (0, -1)
    for right, ch in enumerate(s):
        cnt[ch] += 1
        while len(cnt) > k:
            cnt[s[left]] -= 1
            if cnt[s[left]] == 0:
                del cnt[s[left]]
            left += 1
        if right - left > best[1] - best[0]:
            best = (left, right)
    return s[best[0]:best[1] + 1]


def test_kd_basic():
    assert longest_k_distinct("eceba", 2) == "ece"


def test_kd_one():
    assert longest_k_distinct("aa", 1) == "aa"


def test_kd_empty():
    assert longest_k_distinct("", 2) == ""


def test_kd_zero():
    assert longest_k_distinct("abc", 0) == ""


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
    test_kd_basic()
    test_kd_one()
    test_kd_empty()
    test_kd_zero()
    assert stdlib_only()
    print("str-32 OK: k-distinct")


if __name__ == "__main__":
    main()
