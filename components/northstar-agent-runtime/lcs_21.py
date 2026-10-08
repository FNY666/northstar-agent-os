"""LCS threshold decision (early exit)

What this IS: decides LCS(a,b) >= t without finishing the table, pruning hopeless rows.

What this IS NOT:
* the exact length -- see lcs_01 when the number itself is needed.
* fuzzy matching -- see lcs_36 for a ratio threshold.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_21_VERSION = "lcs-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-21.v1"


def lcs_at_least(a: str, b: str, t: int) -> bool:
    # Row-by-row DP; abort when even the optimistic bound falls short of t.
    m, n = len(a), len(b)
    if t <= 0:
        return True
    if t > min(m, n):
        return False
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        rem = m - i
        bound = 0
        for j in range(n + 1):
            tail = rem if rem < n - j else n - j
            cand = cur[j] + tail
            if cand > bound:
                bound = cand
        if bound < t:
            return False
        prev = cur
    return prev[n] >= t

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
    assert lcs_at_least("abcde", "ace", 3) is True
    assert lcs_at_least("abcde", "ace", 4) is False
    assert lcs_at_least("", "", 0) is True
    assert lcs_at_least("abc", "abc", 3) is True
    assert lcs_at_least("abc", "def", 1) is False
    assert stdlib_only()
    print("21-ok OK")


if __name__ == "__main__":
    main()
