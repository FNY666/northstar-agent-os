"""Maximum uncrossed lines

What this IS: max non-crossing connections between equal values: LCS over int arrays.

What this IS NOT:
* string LCS -- see lcs_01.
* weighted variants -- see lcs_32.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_33_VERSION = "lcs-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-33.v1"


def max_uncrossed_lines(a, b) -> int:
    # Lines (i, j) with a[i] == b[j] must not cross: exactly LCS.
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
    assert max_uncrossed_lines([1, 4, 2], [1, 2, 4]) == 2
    assert max_uncrossed_lines([2, 5, 1, 2, 5], [10, 5, 2, 1, 5, 2]) == 3
    assert max_uncrossed_lines([], [1]) == 0
    assert max_uncrossed_lines([1, 2], [3, 4]) == 0
    assert max_uncrossed_lines([1, 1], [1, 1]) == 2
    assert stdlib_only()
    print("33-ok OK")


if __name__ == "__main__":
    main()
