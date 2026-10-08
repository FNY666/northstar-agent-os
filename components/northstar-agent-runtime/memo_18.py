"""Memoized Word Break Count: memoization example.

Count segmentations of s into dictionary words: for each word matching at i, add count(i + len(word)). The index cache gives O(n * |dict|).

What this IS: a real memoized segmentation counter using a frozenset dictionary.
What this IS NOT: a segmentation enumerator; the host picks the output shape.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_18_VERSION = "memo-word-break-count.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-word-break-count.v1"


class MemoError(Exception):
    """Fail-closed."""


def word_break_count(s: str, words: frozenset, i: int = 0, _cache: dict | None = None) -> int:
    """Memoized word-break segmentation counter."""
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i == len(s):
        cache[i] = 1
    else:
        total = 0
        for w in words:
            if s.startswith(w, i):
                total += word_break_count(s, words, i + len(w), cache)
        cache[i] = total
    return cache[i]

def test_word_break_count_example():
    assert word_break_count("catsanddog", frozenset({"cat", "cats", "and", "sand", "dog"})) == 2


def test_word_break_count_none():
    assert word_break_count("cats", frozenset({"dog"})) == 0


def test_word_break_count_empty():
    assert word_break_count("", frozenset({"a"})) == 1

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
    test_word_break_count_example()
    test_word_break_count_none()
    test_word_break_count_empty()
    assert stdlib_only()
    print("memo-18 OK: word-break-count")


if __name__ == "__main__":
    main()
