"""Valid Palindrome (two-pointer), alphanumeric case-insensitive palindrome check. IS: checks whether a string reads the same forwards and backwards after dropping non-alphanumeric characters and ignoring case, using two pointers. IS NOT: a byte-exact mirror check; punctuation, spaces, and case do not affect the result."""
from __future__ import annotations

import ast

VERSION = "twop-29.v1"


def valid_palindrome(s: str) -> bool:
    """Return True if s is a palindrome considering only alphanumerics, case-insensitively."""
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    lo = 0
    hi = len(s) - 1
    while lo < hi:
        while lo < hi and not s[lo].isalnum():
            lo += 1
        while lo < hi and not s[hi].isalnum():
            hi -= 1
        if s[lo].lower() != s[hi].lower():
            return False
        lo += 1
        hi -= 1
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
    assert valid_palindrome("A man, a plan, a canal: Panama") is True
    assert valid_palindrome("race a car") is False
    assert valid_palindrome("") is True
    assert valid_palindrome("0P") is False
    assert valid_palindrome(".,") is True
    try:
        valid_palindrome(42)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-string input")
    print("twop-29 OK")


if __name__ == "__main__":
    main()
