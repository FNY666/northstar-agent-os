"""Count common subsequences

What this IS: number of distinct-position common subsequences (duplicates counted).

What this IS NOT:
* just the longest -- see lcs_01.
* distinct-subsequence counting -- duplicates are not deduped here.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_41_VERSION = "lcs-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-41.v1"


def count_common_subseq(a: str, b: str) -> int:
    # Match: new subseqs pair every prior one with this char (+1 for itself).
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j] + dp[i][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] + dp[i][j - 1] - dp[i - 1][j - 1]
    return dp[m][n]

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
    assert count_common_subseq("a", "a") == 1
    assert count_common_subseq("ab", "ab") == 3
    assert count_common_subseq("abc", "abc") == 7
    assert count_common_subseq("", "a") == 0
    assert count_common_subseq("a", "b") == 0
    assert stdlib_only()
    print("41-ok OK")


if __name__ == "__main__":
    main()
