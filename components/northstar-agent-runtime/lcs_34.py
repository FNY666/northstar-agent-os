"""Subsequence check

What this IS: two-pointer test whether a is a subsequence of b (LCS(a,b) == len(a)).

What this IS NOT:
* full LCS machinery -- overkill here; this is O(|a|+|b|).
* fuzzy matching -- see lcs_36.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_34_VERSION = "lcs-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-34.v1"


def is_subsequence(a: str, b: str) -> bool:
    # Greedy left-to-right scan; optimal for the subsequence decision.
    it = iter(b)
    return all(c in it for c in a)

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
    assert is_subsequence("abc", "ahbgdc") is True
    assert is_subsequence("axc", "ahbgdc") is False
    assert is_subsequence("", "abc") is True
    assert is_subsequence("abc", "") is False
    assert is_subsequence("ace", "abcde") is True
    assert stdlib_only()
    print("34-ok OK")


if __name__ == "__main__":
    main()
