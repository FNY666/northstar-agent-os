"""Longest common substring length

What this IS: length of the longest contiguous block common to both strings (not subsequence).

What this IS NOT:
* the subsequence variant -- see lcs_01 for non-contiguous LCS.
* the substring itself -- see lcs_06 for reconstruction.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_05_VERSION = "lcs-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-05.v1"


def lcsubstring_length(a: str, b: str) -> int:
    # Contiguous match: reset on mismatch, O(m*n) time / O(n) space.
    n = len(b)
    prev = [0] * (n + 1)
    best = 0
    for i in range(1, len(a) + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best

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
    assert lcsubstring_length("abcde", "abfce") == 2
    assert lcsubstring_length("abcd", "efgh") == 0
    assert lcsubstring_length("abc", "abc") == 3
    assert lcsubstring_length("", "a") == 0
    assert lcsubstring_length("ababa", "baba") == 4
    assert stdlib_only()
    print("05-ok OK")


if __name__ == "__main__":
    main()
