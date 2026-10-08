"""Reverse Vowels (two-pointer), reverse only vowels in a string. IS: swaps vowel characters from both ends toward the middle, leaving consonants and all other characters in place. IS NOT: a full string reversal; only a, e, i, o, u (either case) move."""
from __future__ import annotations

import ast

VERSION = "twop-28.v1"

VOWELS = frozenset("aeiouAEIOU")


def reverse_vowels(s: str) -> str:
    """Return a new string with the vowel characters reversed in place order."""
    if not isinstance(s, str):
        raise ValueError("input must be a string")
    chars = list(s)
    lo = 0
    hi = len(chars) - 1
    while lo < hi:
        if chars[lo] not in VOWELS:
            lo += 1
        elif chars[hi] not in VOWELS:
            hi -= 1
        else:
            chars[lo], chars[hi] = chars[hi], chars[lo]
            lo += 1
            hi -= 1
    return "".join(chars)


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
    assert reverse_vowels("hello") == "holle"
    assert reverse_vowels("leetcode") == "leotcede"
    assert reverse_vowels("bcdfg") == "bcdfg"
    assert reverse_vowels("") == ""
    assert reverse_vowels("AEio") == "oiEA"
    try:
        reverse_vowels(None)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for non-string input")
    print("twop-28 OK")


if __name__ == "__main__":
    main()
