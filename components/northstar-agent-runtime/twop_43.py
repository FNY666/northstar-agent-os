"""max_vowels_in_substring_k (two-pointer), max vowels in any length-k substring. IS: a fixed-size sliding window counting vowels (case-insensitive). IS NOT: a scanner over all substring lengths."""
from __future__ import annotations

import ast

VERSION = "twop-43.v1"

_VOWELS = frozenset("aeiouAEIOU")


def max_vowels_in_substring_k(s: str, k: int) -> int:
    """Return the max number of vowels in any substring of s of length k."""
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if k <= 0:
        raise ValueError("k must be positive")
    if k > len(s):
        raise ValueError("k must not exceed len(s)")
    cur = sum(1 for ch in s[:k] if ch in _VOWELS)
    best = cur
    for i in range(k, len(s)):
        if s[i - k] in _VOWELS:
            cur -= 1
        if s[i] in _VOWELS:
            cur += 1
        if cur > best:
            best = cur
    return best


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert max_vowels_in_substring_k("abciiidef", 3) == 3
    assert max_vowels_in_substring_k("aeiou", 2) == 2
    assert max_vowels_in_substring_k("leetcode", 3) == 2
    assert max_vowels_in_substring_k("rhythms", 3) == 0  # edge: no vowels
    assert max_vowels_in_substring_k("abc", 3) == 1
    try:
        max_vowels_in_substring_k("abc", 0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for k=0")
    try:
        max_vowels_in_substring_k("ab", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for k > len(s)")
    assert stdlib_only()
    print("max_vowels_in_substring_k OK")


if __name__ == "__main__":
    main()
