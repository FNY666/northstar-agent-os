"""LCS over generic sequences

What this IS: LCS length for arbitrary sequences (e.g. lists of ints), not just strings.

What this IS NOT:
* the string-specialized version -- see lcs_01.
* a custom equality predicate -- see lcs_27.
"""

from __future__ import annotations

import ast
from typing import Sequence
#: Module version.
LCS_19_VERSION = "lcs-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-19.v1"


def lcs_seq(a: Sequence, b: Sequence) -> int:
    # Same DP as lcs_01 but element comparison is generic.
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for x in a:
        cur = [0] * (n + 1)
        for j in range(1, n + 1):
            if x == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[n]

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
    assert lcs_seq([1, 2, 3, 4], [2, 4]) == 2
    assert lcs_seq([], [1]) == 0
    assert lcs_seq([1, 1, 1], [1, 1]) == 2
    assert lcs_seq("abcde", "ace") == 3
    assert lcs_seq((1, 2), (3, 4)) == 0
    assert stdlib_only()
    print("19-ok OK")


if __name__ == "__main__":
    main()
