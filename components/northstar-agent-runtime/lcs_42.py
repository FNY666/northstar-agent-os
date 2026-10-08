"""Containment similarity

What this IS: LCS(a,b) / min(|a|,|b|): how much of the shorter string is contained.

What this IS NOT:
* Dice similarity -- see lcs_17 (symmetric normalization).
* fuzzy threshold -- see lcs_36.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_42_VERSION = "lcs-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-42.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def containment(a: str, b: str) -> float:
    # 1.0 means the shorter string is fully contained in the longer.
    m = min(len(a), len(b))
    if m == 0:
        return 0.0
    return _lcs_len(a, b) / m

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
    assert containment("abc", "xxabcyy") == 1.0
    assert containment("abc", "def") == 0.0
    assert containment("", "a") == 0.0
    assert abs(containment("abcde", "ace") - 1.0) < 1e-9
    assert abs(containment("abc", "abd") - (2 / 3)) < 1e-9
    assert stdlib_only()
    print("42-ok OK")


if __name__ == "__main__":
    main()
