"""Insert/delete-only edit distance

What this IS: minimum insertions+deletions to convert a into b: |a| + |b| - 2*LCS.

What this IS NOT:
* Levenshtein distance -- substitutions cost 1 there, 2 here.
* the LCS itself -- see lcs_01.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_16_VERSION = "lcs-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-16.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def ins_del_distance(a: str, b: str) -> int:
    # Shared LCS chars are kept; everything else is deleted/inserted.
    return len(a) + len(b) - 2 * _lcs_len(a, b)

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
    assert ins_del_distance("sea", "eat") == 2
    assert ins_del_distance("", "abc") == 3
    assert ins_del_distance("abc", "abc") == 0
    assert ins_del_distance("a", "b") == 2
    assert ins_del_distance("abcde", "ace") == 2
    assert stdlib_only()
    print("16-ok OK")


if __name__ == "__main__":
    main()
