"""LCS case-insensitive

What this IS: LCS after casefolding both inputs.

What this IS NOT:
* unicode normalization -- see lcs_44 for NFKD handling.
* custom predicates -- see lcs_27.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_23_VERSION = "lcs-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-23.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def lcs_nocase(a: str, b: str) -> int:
    # Casefold (stronger than lower) then plain LCS.
    return _lcs_len(a.casefold(), b.casefold())

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
    assert lcs_nocase("AbC", "abc") == 3
    assert lcs_nocase("Hello", "hello") == 5
    assert lcs_nocase("ABC", "def") == 0
    assert lcs_nocase("", "a") == 0
    assert lcs_nocase("abcde", "ACE") == 3
    assert stdlib_only()
    print("23-ok OK")


if __name__ == "__main__":
    main()
