"""strStr (needle in haystack): KMP-based first occurrence.

Returns the first index of needle in haystack, -1 if absent; empty needle -> 0.

What this IS: a real KMP implementation.
What this IS NOT: a naive fallback for tiny inputs.
"""

from __future__ import annotations

import ast

#: Module version.
STR_46_VERSION = "str-strstr.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-strstr.v1"


class StrError(Exception):
    """Fail-closed."""


def _lps(pattern: str) -> list:
    lps = [0] * len(pattern)
    length, i = 0, 1
    while i < len(pattern):
        if pattern[i] == pattern[length]:
            length += 1
            lps[i] = length
            i += 1
        elif length:
            length = lps[length - 1]
        else:
            i += 1
    return lps


def str_str(haystack: str, needle: str) -> int:
    """First index of needle in haystack; -1 if absent."""
    if not needle:
        return 0
    lps = _lps(needle)
    i = j = 0
    while i < len(haystack):
        if haystack[i] == needle[j]:
            i += 1
            j += 1
        if j == len(needle):
            return i - j
        elif i < len(haystack) and haystack[i] != needle[j]:
            if j:
                j = lps[j - 1]
            else:
                i += 1
    return -1


def test_ss_basic():
    assert str_str("hello", "ll") == 2


def test_ss_missing():
    assert str_str("aaaaa", "bba") == -1


def test_ss_empty_needle():
    assert str_str("abc", "") == 0


def test_ss_start():
    assert str_str("abc", "abc") == 0


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
    test_ss_basic()
    test_ss_missing()
    test_ss_empty_needle()
    test_ss_start()
    assert stdlib_only()
    print("str-46 OK: strstr")


if __name__ == "__main__":
    main()
