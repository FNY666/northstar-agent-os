"""Backtracking: Letter case permutation -- enumerate every string formed by
choosing upper or lower case for each letter in the input.

IS: position-by-position branching over letters only; digits and other
characters are carried through unchanged, preserving relative order.
IS NOT: anagram/permutation of characters, locale-aware case folding, or
duplicate elimination -- each letter doubles the output count.
"""

from __future__ import annotations

VERSION = "backtrack_46.v1"


import ast
from typing import List

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def letter_case_permutation(s: str) -> List[str]:
    """Return all case permutations of s (digits/other chars stay fixed)."""
    results: List[str] = []
    chars = list(s)

    def backtrack(i: int) -> None:
        if i == len(chars):
            results.append("".join(chars))
            return
        if chars[i].isalpha():
            chars[i] = chars[i].lower()
            backtrack(i + 1)
            chars[i] = chars[i].upper()
            backtrack(i + 1)
        else:
            backtrack(i + 1)

    backtrack(0)
    return results


def stdlib_only() -> bool:
    """Return True only if every import in this file comes from the allowed stdlib set."""
    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.module.split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    assert sorted(letter_case_permutation("a1b2")) == ["A1B2", "A1b2", "a1B2", "a1b2"]
    assert sorted(letter_case_permutation("3z4")) == ["3Z4", "3z4"]
    assert letter_case_permutation("12345") == ["12345"]
    assert letter_case_permutation("") == [""]
    assert len(letter_case_permutation("Ab")) == 4
    print("backtrack_46 OK")


if __name__ == "__main__":
    main()
