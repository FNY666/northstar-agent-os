"""Distinct subsequence count: O(n) DP with last occurrence.

dp doubles each char, subtracts the count from the char's previous occurrence to dedupe.

What this IS: a real O(n) implementation (mod 1e9+7).
What this IS NOT: exact big-int counts (drop the mod).
"""

from __future__ import annotations

import ast

#: Module version.
STR_49_VERSION = "str-distinct-subseq.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-distinct-subseq-count.v1"


class StrError(Exception):
    """Fail-closed."""


def count_distinct_subseq(s: str) -> int:
    """Count distinct non-empty subsequences of s (mod 1e9+7)."""
    MOD = 10 ** 9 + 7
    dp = 1
    last = {}
    for ch in s:
        new = (dp * 2) % MOD
        if ch in last:
            new = (new - last[ch]) % MOD
        last[ch] = dp
        dp = new
    return (dp - 1) % MOD


def test_ds_abc():
    assert count_distinct_subseq("abc") == 7


def test_ds_repeat():
    assert count_distinct_subseq("aaa") == 3


def test_ds_empty():
    assert count_distinct_subseq("") == 0


def test_ds_aba():
    assert count_distinct_subseq("aba") == 6


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
    test_ds_abc()
    test_ds_repeat()
    test_ds_empty()
    test_ds_aba()
    assert stdlib_only()
    print("str-49 OK: distinct-subseq")


if __name__ == "__main__":
    main()
