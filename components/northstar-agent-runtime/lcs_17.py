"""Dice similarity via LCS

What this IS: Dice coefficient 2*LCS/(|a|+|b|): 1.0 for identical, 0.0 for disjoint.

What this IS NOT:
* containment -- see lcs_42 for LCS/min(|a|,|b|).
* Jaccard over k-grams -- a different similarity family.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_17_VERSION = "lcs-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-17.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def dice_lcs(a: str, b: str) -> float:
    # Twice the shared subsequence over the total length.
    if not a and not b:
        return 0.0
    return (2.0 * _lcs_len(a, b)) / (len(a) + len(b))

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
    assert dice_lcs("abc", "abc") == 1.0
    assert dice_lcs("abc", "def") == 0.0
    assert dice_lcs("", "") == 0.0
    assert abs(dice_lcs("abcde", "ace") - 0.75) < 1e-9
    assert dice_lcs("", "a") == 0.0
    assert stdlib_only()
    print("17-ok OK")


if __name__ == "__main__":
    main()
