"""Word-break count: split at every prefix, memoised

Counts segmentations of s into dictionary words.

What this IS: a real memoised recursive word-break counter.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_44_VERSION = "rec-word-break.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-word-break.v1"


class RecError(Exception):
    """Fail-closed."""


def word_break_count(s: str, words) -> int:
    """Number of ways to segment s with words."""
    wordset = set(words)
    memo = {}

    def rec(i) -> int:
        if i == len(s):
            return 1
        if i in memo:
            return memo[i]
        total = 0
        for j in range(i + 1, len(s) + 1):
            if s[i:j] in wordset:
                total += rec(j)
        memo[i] = total
        return total

    return rec(0)

def test_word_break_basic():
    assert word_break_count("catsanddog", ["cat", "cats", "and", "sand", "dog"]) == 2


def test_word_break_none():
    assert word_break_count("abc", ["d"]) == 0


def test_word_break_empty():
    assert word_break_count("", ["a"]) == 1


def test_word_break_single():
    assert word_break_count("a", ["a"]) == 1

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_word_break_basic()
    test_word_break_none()
    test_word_break_empty()
    test_word_break_single()
    assert stdlib_only()
    print("rec-word-break OK")


if __name__ == "__main__":
    main()
