"""LCS via explicit stack

What this IS: iterative post-order DP with an explicit stack: no recursion-limit risk.

What this IS NOT:
* recursive memoization -- see lcs_04.
* lru_cache recursion -- see lcs_31.
"""

from __future__ import annotations

import ast
from typing import Dict, Tuple
#: Module version.
LCS_49_VERSION = "lcs-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-49.v1"


def lcs_stack(a: str, b: str) -> int:
    # Simulate the memoized recursion iteratively.
    m, n = len(a), len(b)
    memo: Dict[Tuple[int, int], int] = {}
    stack = [(m, n, False)]
    while stack:
        i, j, done = stack.pop()
        if i == 0 or j == 0:
            memo[(i, j)] = 0
            continue
        if (i, j) in memo:
            continue
        if not done:
            stack.append((i, j, True))
            if a[i - 1] == b[j - 1]:
                stack.append((i - 1, j - 1, False))
            else:
                stack.append((i - 1, j, False))
                stack.append((i, j - 1, False))
        else:
            if a[i - 1] == b[j - 1]:
                memo[(i, j)] = memo[(i - 1, j - 1)] + 1
            else:
                x, y = memo[(i - 1, j)], memo[(i, j - 1)]
                memo[(i, j)] = x if x >= y else y
    return memo[(m, n)]

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
    assert lcs_stack("abcde", "ace") == 3
    assert lcs_stack("", "abc") == 0
    assert lcs_stack("abc", "abc") == 3
    assert lcs_stack("abc", "def") == 0
    assert lcs_stack("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("49-ok OK")


if __name__ == "__main__":
    main()
