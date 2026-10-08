"""Valid Palindrome II (two-pointer), palindrome after deleting at most one char. IS: checks whether a string can become a palindrome by deleting no more than one character, skipping either side at the first mismatch. IS NOT: a two-deletion or arbitrary-edit check; more than one deletion is not allowed."""
from __future__ import annotations

import ast

VERSION = "twop-30.v1"


def _is_pal_range(s: str, lo: int, hi: int) -> bool:
    while lo < hi:
        if s[lo] != s[hi]:
            return False
        lo += 1
        hi -= 1
    return True


def valid_palindrome_ii(s: str) -> bool:
    """Return True if s is a palindrome after deleting at most one character."""
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    lo = 0
    hi = len(s) - 1
    while lo < hi:
        if s[lo] == s[hi]:
            lo += 1
            hi -= 1
        else:
            return _is_pal_range(s, lo + 1, hi) or _is_pal_range(s, lo, hi - 1)
    return True


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
    assert valid_palindrome_ii("aba") is True
    assert valid_palindrome_ii("abca") is True
    assert valid_palindrome_ii("abc") is False
    assert valid_palindrome_ii("a") is True
    assert valid_palindrome_ii("deeee") is True
    assert valid_palindrome_ii("abccaa") is False
    try:
        valid_palindrome_ii(3.14)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-string input")
    print("twop-30 OK")


if __name__ == "__main__":
    main()
