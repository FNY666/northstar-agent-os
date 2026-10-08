"""Boyer-Moore search: sublinear average-time substring search.

Scans the pattern right-to-left and shifts by the bad-character rule, often skipping m characters per step for large alphabets.

What this IS: a real bad-character implementation.
What this IS NOT: the full Galil rule; good-suffix is future work.
"""

from __future__ import annotations

import ast

#: Module version.
STR_02_VERSION = "str-boyer-moore.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-boyer-moore.v1"


class StrError(Exception):
    """Fail-closed."""


def _bad_char(pattern: str) -> dict:
    """Last occurrence of each character in the pattern."""
    table = {}
    for i, ch in enumerate(pattern):
        table[ch] = i
    return table


def boyer_moore_search(text: str, pattern: str) -> list:
    """Return start indices of all occurrences of pattern in text."""
    if not pattern:
        return []
    m, n = len(pattern), len(text)
    table = _bad_char(pattern)
    res = []
    s = 0
    while s <= n - m:
        j = m - 1
        while j >= 0 and pattern[j] == text[s + j]:
            j -= 1
        if j < 0:
            res.append(s)
            s += 1
        else:
            s += max(1, j - table.get(text[s + j], -1))
    return res


def test_bm_basic():
    assert boyer_moore_search("ABAAABCD", "ABC") == [4]


def test_bm_overlap():
    assert boyer_moore_search("AAAA", "AA") == [0, 1, 2]


def test_bm_none():
    assert boyer_moore_search("hello", "world") == []


def test_bm_empty():
    assert boyer_moore_search("abc", "") == []


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
    test_bm_basic()
    test_bm_overlap()
    test_bm_none()
    test_bm_empty()
    assert stdlib_only()
    print("str-02 OK: boyer-moore")


if __name__ == "__main__":
    main()
