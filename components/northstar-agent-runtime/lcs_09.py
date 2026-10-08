"""Shortest common supersequence length

What this IS: length of the shortest string having both inputs as subsequences: m + n - LCS.

What this IS NOT:
* the supersequence itself -- see lcs_10 for reconstruction.
* edit distance -- substitutions are not allowed here.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_09_VERSION = "lcs-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-09.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def scs_length(a: str, b: str) -> int:
    # Every LCS char is shared once; everything else appears from both strings.
    return len(a) + len(b) - _lcs_len(a, b)

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
    assert scs_length("abac", "cab") == 5
    assert scs_length("abc", "abc") == 3
    assert scs_length("", "ab") == 2
    assert scs_length("ab", "cd") == 4
    assert scs_length("abcde", "ace") == 5
    assert stdlib_only()
    print("09-ok OK")


if __name__ == "__main__":
    main()
