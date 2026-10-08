"""Longest common substring (reconstruction)

What this IS: returns one longest contiguous common substring.

What this IS NOT:
* the length-only variant -- see lcs_05.
* non-contiguous subsequence -- see lcs_03.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_06_VERSION = "lcs-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-06.v1"


def lcsubstring(a: str, b: str) -> str:
    # Track where the best run ends, then slice it out.
    n = len(b)
    prev = [0] * (n + 1)
    best, end = 0, 0
    for i in range(1, len(a) + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best, end = cur[j], i
        prev = cur
    return a[end - best:end]

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
    assert lcsubstring("abcde", "abfce") == "ab"
    s = lcsubstring("ababa", "baba")
    assert s == "baba" and s in "ababa" and s in "baba"
    assert lcsubstring("abcd", "efgh") == ""
    assert lcsubstring("abc", "abc") == "abc"
    assert lcsubstring("", "a") == ""
    assert stdlib_only()
    print("06-ok OK")


if __name__ == "__main__":
    main()
