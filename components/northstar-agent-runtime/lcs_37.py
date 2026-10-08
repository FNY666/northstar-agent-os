"""Gapped alignment from LCS

What this IS: two equal-length strings with '-' gaps showing one optimal alignment.

What this IS NOT:
* diff opcodes -- see lcs_26 for the edit-script view.
* unified diff lines -- see lcs_38.
"""

from __future__ import annotations

import ast
from typing import Tuple
#: Module version.
LCS_37_VERSION = "lcs-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-37.v1"


def lcs_align(a: str, b: str) -> Tuple[str, str]:
    # Backtrack, emitting gaps so both rows line up.
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = dp[i - 1][j] if dp[i - 1][j] >= dp[i][j - 1] else dp[i][j - 1]
    i, j, top, bot = m, n, [], []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            top.append(a[i - 1])
            bot.append(b[j - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            top.append(a[i - 1])
            bot.append("-")
            i -= 1
        else:
            top.append("-")
            bot.append(b[j - 1])
            j -= 1
    while i > 0:
        top.append(a[i - 1])
        bot.append("-")
        i -= 1
    while j > 0:
        top.append("-")
        bot.append(b[j - 1])
        j -= 1
    return "".join(reversed(top)), "".join(reversed(bot))

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
    top, bot = lcs_align("abcde", "ace")
    assert top == "abcde" and bot == "a-c-e"
    top, bot = lcs_align("", "ab")
    assert top == "--" and bot == "ab"
    top, bot = lcs_align("abc", "abc")
    assert top == bot == "abc"
    top, bot = lcs_align("ab", "ba")
    assert len(top) == len(bot) and top.replace("-", "") == "ab"
    assert bot.replace("-", "") == "ba"
    assert stdlib_only()
    print("37-ok OK")


if __name__ == "__main__":
    main()
