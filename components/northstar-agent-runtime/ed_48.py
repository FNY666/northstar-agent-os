"""Edit operation counts

Distance plus the breakdown into substitutions/insertions/deletions.

What this IS: a backtrace that counts each operation kind.

What this IS NOT:
* the op list -- ed_28 returns the concrete sequence.
* distance only -- the (sub, ins, del) triple comes along.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_48_VERSION = "ed-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-48.v1"


def edit_operation_counts(a: str, b: str) -> Tuple[int, int, int, int]:
    """(distance, substitutions, insertions, deletions)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
    sub = ins = dele = 0
    i, j = m, n
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if dp[i][j] == dp[i - 1][j - 1] + cost:
                if cost:
                    sub += 1
                i -= 1
                j -= 1
                continue
        if i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            dele += 1
            i -= 1
            continue
        ins += 1
        j -= 1
    return (dp[m][n], sub, ins, dele)

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
    d, s, ins, dele = edit_operation_counts("kitten", "sitting")
    assert d == 3
    assert s + ins + dele == 3
    assert edit_operation_counts("abc", "abc") == (0, 0, 0, 0)
    assert edit_operation_counts("", "ab") == (2, 0, 2, 0)
    assert edit_operation_counts("ab", "") == (2, 0, 0, 2)
    try:
        edit_operation_counts("a", 7)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("48-op-counts OK")


if __name__ == "__main__":
    main()
