"""Banded LCS

What this IS: LCS restricted to |i - j| <= w: fast when the strings are already similar.

What this IS NOT:
* full LCS -- use a large w to recover the exact answer.
* threshold decision -- see lcs_21.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_46_VERSION = "lcs-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-46.v1"


def lcs_banded(a: str, b: str, w: int) -> int:
    # Only cells near the main diagonal are evaluated.
    m, n = len(a), len(b)
    NEG = -(10 ** 9)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [NEG] * (n + 1)
        cur[0] = 0
        lo, hi = max(1, i - w), min(n, i + w)
        for j in range(lo, hi + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                up = prev[j]
                left = cur[j - 1]
                cur[j] = up if up >= left else left
        prev = cur
    return prev[n] if prev[n] > NEG // 2 else 0

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
    assert lcs_banded("abc", "abc", 0) == 3
    assert lcs_banded("abc", "abc", 5) == 3
    assert lcs_banded("", "a", 2) == 0
    assert lcs_banded("abcde", "ace", 10) == 3
    assert lcs_banded("abc", "def", 2) == 0
    assert stdlib_only()
    print("46-ok OK")


if __name__ == "__main__":
    main()
