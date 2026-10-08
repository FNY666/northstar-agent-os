"""Finite-automaton matching: precomputed transition search.

Builds delta(q, ch) for the pattern, then scans text in O(n).

What this IS: a real automaton matcher.
What this IS NOT: alphabet compression for huge alphabets.
"""

from __future__ import annotations

import ast

#: Module version.
STR_22_VERSION = "str-fa-matching.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-finite-automaton-matching.v1"


class StrError(Exception):
    """Fail-closed."""


def build_transition(pattern: str, alphabet) -> list:
    """delta[q][ch] for q in 0..m."""
    m = len(pattern)
    trans = []
    for q in range(m + 1):
        row = {}
        for ch in alphabet:
            k = min(m, q + 1)
            cand = pattern[:q] + ch
            while k > 0 and not cand.endswith(pattern[:k]):
                k -= 1
            row[ch] = k
        trans.append(row)
    return trans


def fa_search(text: str, pattern: str, alphabet=None) -> list:
    """Return start indices of all occurrences."""
    if not pattern:
        return []
    if alphabet is None:
        alphabet = set(text + pattern)
    trans = build_transition(pattern, alphabet)
    res = []
    q = 0
    for i, ch in enumerate(text):
        q = trans[q].get(ch, 0)
        if q == len(pattern):
            res.append(i - len(pattern) + 1)
    return res


def test_fa_basic():
    assert fa_search("ABABDABACDABABCABAB", "ABABCABAB") == [10]


def test_fa_overlap():
    assert fa_search("AAAA", "AA") == [0, 1, 2]


def test_fa_none():
    assert fa_search("hello", "world") == []


def test_fa_empty():
    assert fa_search("abc", "") == []


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
    test_fa_basic()
    test_fa_overlap()
    test_fa_none()
    test_fa_empty()
    assert stdlib_only()
    print("str-22 OK: fa-matching")


if __name__ == "__main__":
    main()
