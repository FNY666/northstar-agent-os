"""Reverse String Inplace (two-pointer), reverse list of chars in-place. IS: reverses a list of single-character strings in place with two pointers swapping from both ends. IS NOT: a string-returning helper; it mutates the given list and requires one-char elements."""
from __future__ import annotations

import ast

VERSION = "twop-26.v1"


def reverse_string_inplace(chars: list[str]) -> None:
    """Reverse the list of single-character strings in place."""
    if not isinstance(chars, list):
        raise ValueError("input must be a list")
    for c in chars:
        if not isinstance(c, str) or len(c) != 1:
            raise ValueError("input must be a list of single-character strings")
    lo = 0
    hi = len(chars) - 1
    while lo < hi:
        chars[lo], chars[hi] = chars[hi], chars[lo]
        lo += 1
        hi -= 1


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] not in allowed for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    chars = ["h", "e", "l", "l", "o"]
    reverse_string_inplace(chars)
    assert chars == ["o", "l", "l", "e", "h"]
    empty: list[str] = []
    reverse_string_inplace(empty)
    assert empty == []
    single = ["x"]
    reverse_string_inplace(single)
    assert single == ["x"]
    try:
        reverse_string_inplace(["ab", "c"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for multi-char element")
    print("twop-26 OK")


if __name__ == "__main__":
    main()
