"""Online LCS (streaming)

What this IS: LCS where b arrives as an iterator; one DP row is kept per consumed char.

What this IS NOT:
* batch LCS -- see lcs_02 for the non-streaming version.
* full table -- streaming keeps no history.
"""

from __future__ import annotations

import ast
from typing import Iterable
#: Module version.
LCS_35_VERSION = "lcs-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-35.v1"


def online_lcs_length(a: str, b_iter: Iterable[str]) -> int:
    # a is fixed as columns; each streamed char of b advances one row.
    prev = [0] * (len(a) + 1)
    for ch in b_iter:
        cur = [0] * (len(a) + 1)
        for i, ca in enumerate(a, 1):
            if ca == ch:
                cur[i] = prev[i - 1] + 1
            else:
                cur[i] = prev[i] if prev[i] >= cur[i - 1] else cur[i - 1]
        prev = cur
    return prev[len(a)]

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
    assert online_lcs_length("abcde", iter("ace")) == 3
    assert online_lcs_length("abcde", iter("")) == 0
    assert online_lcs_length("", iter("abc")) == 0
    assert online_lcs_length("abc", iter("abc")) == 3
    assert online_lcs_length("AGGTAB", iter("GXTXAYB")) == 4
    assert stdlib_only()
    print("35-ok OK")


if __name__ == "__main__":
    main()
