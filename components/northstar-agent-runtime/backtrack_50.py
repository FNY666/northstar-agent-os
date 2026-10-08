"""Backtracking: Maximum length of concatenated unique-character strings --
pick a subsequence of the given strings whose concatenation has no repeated
character, maximizing its total length.

IS: backtracking over include/skip choices with each candidate string
encoded as a bitmask; strings with internal duplicates are discarded
up front and overlap is tested by bit intersection.
IS NOT: concatenation order optimization (order does not affect the
maximum length), nor the k-string variant -- any subsequence size is
allowed, only total unique length is maximized.
"""

from __future__ import annotations

VERSION = "backtrack_50.v1"


import ast
from typing import List

_ALLOWED_IMPORTS = {"__future__", "ast", "typing", "dataclasses", "itertools",
                    "functools", "collections", "math", "re", "string", "sys"}


def _to_mask(s: str) -> int | None:
    """Bitmask of chars in s, or None if s has a repeated character."""
    mask = 0
    for ch in s:
        bit = 1 << (ord(ch) - ord("a"))
        if mask & bit:
            return None
        mask |= bit
    return mask


def max_length(arr: List[str]) -> int:
    """Return the max length of a concatenation of strings with all unique chars."""
    masks = [m for m in (_to_mask(s) for s in arr) if m is not None]
    best = 0

    def backtrack(i: int, used: int) -> None:
        nonlocal best
        length = bin(used).count("1")
        if length > best:
            best = length
        for j in range(i, len(masks)):
            if used & masks[j] == 0:  # no shared characters
                backtrack(j + 1, used | masks[j])

    backtrack(0, 0)
    return best


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
    assert max_length(["un", "iq", "ue"]) == 4
    assert max_length(["cha", "r", "act", "ers"]) == 6
    assert max_length(["abcdefghijklmnopqrstuvwxyz"]) == 26
    assert max_length(["aa", "bb"]) == 0
    assert max_length([]) == 0
    print("backtrack_50 OK")


if __name__ == "__main__":
    main()
