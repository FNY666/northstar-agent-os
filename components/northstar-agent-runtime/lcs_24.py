"""Word-level LCS length

What this IS: LCS over whitespace-separated tokens instead of characters.

What this IS NOT:
* character LCS -- see lcs_01.
* word reconstruction -- see lcs_25.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_24_VERSION = "lcs-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-24.v1"


def lcs_words_length(a: str, b: str) -> int:
    # Tokenize on whitespace, then generic sequence LCS.
    ta, tb = a.split(), b.split()
    prev = [0] * (len(tb) + 1)
    for w in ta:
        cur = [0] * (len(tb) + 1)
        for j in range(1, len(tb) + 1):
            if w == tb[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[len(tb)]

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
    assert lcs_words_length("the cat sat", "the dog sat") == 2
    assert lcs_words_length("a b c", "a b c") == 3
    assert lcs_words_length("a b", "c d") == 0
    assert lcs_words_length("", "x y") == 0
    assert lcs_words_length("hello world", "hello") == 1
    assert stdlib_only()
    print("24-ok OK")


if __name__ == "__main__":
    main()
