"""Diff opcodes from LCS

What this IS: merged (equal|delete|insert) spans describing how to turn a into b.

What this IS NOT:
* line-oriented diff text -- see lcs_38.
* gapped alignment -- see lcs_37.
"""

from __future__ import annotations

import ast
from typing import List, Tuple
#: Module version.
LCS_26_VERSION = "lcs-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-26.v1"


def diff_opcodes(a: str, b: str) -> List[Tuple[str, str]]:
    # Backtrack the LCS table, then merge runs of equal ops.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, ops = m, n, []
    while i > 0 or j > 0:
        if i > 0 and j > 0 and a[i - 1] == b[j - 1]:
            ops.append(("equal", a[i - 1]))
            i -= 1
            j -= 1
        elif j > 0 and (i == 0 or dp[i][j - 1] >= dp[i - 1][j]):
            ops.append(("insert", b[j - 1]))
            j -= 1
        else:
            ops.append(("delete", a[i - 1]))
            i -= 1
    ops.reverse()
    merged = []
    for op, ch in ops:
        if merged and merged[-1][0] == op:
            merged[-1] = (op, merged[-1][1] + ch)
        else:
            merged.append((op, ch))
    return merged

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
    assert diff_opcodes("abcde", "ace") == [("equal", "a"), ("delete", "b"), ("equal", "c"), ("delete", "d"), ("equal", "e")]
    assert diff_opcodes("", "ab") == [("insert", "ab")]
    assert diff_opcodes("ab", "") == [("delete", "ab")]
    assert diff_opcodes("abc", "abc") == [("equal", "abc")]
    ops = diff_opcodes("kitten", "sitting")
    assert ops[0] == ("delete", "k") and ops[-1] == ("insert", "g")
    assert stdlib_only()
    print("26-ok OK")


if __name__ == "__main__":
    main()
