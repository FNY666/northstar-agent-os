"""Unified-style diff lines

What this IS: character-level diff lines ('  x' keep, '- x' delete, '+ x' insert).

What this IS NOT:
* merged opcodes -- see lcs_26.
* gapped alignment -- see lcs_37.
"""

from __future__ import annotations

import ast
from typing import List
#: Module version.
LCS_38_VERSION = "lcs-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-38.v1"


def diff_lines(a: str, b: str) -> List[str]:
    # Per-character diff lines derived from the LCS backtrack.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, out = m, n, []
    while i > 0 or j > 0:
        if i > 0 and j > 0 and a[i - 1] == b[j - 1]:
            out.append("  " + a[i - 1])
            i -= 1
            j -= 1
        elif j > 0 and (i == 0 or dp[i][j - 1] >= dp[i - 1][j]):
            out.append("+ " + b[j - 1])
            j -= 1
        else:
            out.append("- " + a[i - 1])
            i -= 1
    return list(reversed(out))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "typing"}
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
    assert diff_lines("abcde", "ace") == ["  a", "- b", "  c", "- d", "  e"]
    assert diff_lines("", "ab") == ["+ a", "+ b"]
    assert diff_lines("ab", "") == ["- a", "- b"]
    assert diff_lines("abc", "abc") == ["  a", "  b", "  c"]
    assert diff_lines("", "") == []
    assert stdlib_only()
    print("38-ok OK")


if __name__ == "__main__":
    main()
