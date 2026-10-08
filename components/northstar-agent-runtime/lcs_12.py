"""Minimum insertions to make palindrome

What this IS: fewest insertions to turn s into a palindrome: len(s) - LPS(s).

What this IS NOT:
* minimum deletions -- see lcs_11 (equal count by symmetry).
* edit distance with substitutions -- not covered here.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_12_VERSION = "lcs-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-12.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def min_ins_to_palindrome(s: str) -> int:
    # Mirror of deletions: insert the missing mirror characters.
    return len(s) - _lcs_len(s, s[::-1])

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    assert min_ins_to_palindrome("bbbab") == 1
    assert min_ins_to_palindrome("cbbd") == 2
    assert min_ins_to_palindrome("a") == 0
    assert min_ins_to_palindrome("") == 0
    assert min_ins_to_palindrome("abcd") == 3
    assert stdlib_only()
    print("12-ok OK")


if __name__ == "__main__":
    main()
