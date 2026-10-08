"""LCS with unicode normalization

What this IS: LCS after NFKD normalization so composed/decomposed forms match.

What this IS NOT:
* case-insensitivity -- see lcs_23.
* plain LCS -- see lcs_01.
"""

from __future__ import annotations

import ast
import unicodedata
#: Module version.
LCS_44_VERSION = "lcs-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-44.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def lcs_nfkd(a: str, b: str) -> int:
    # Normalize first: "é" (U+00E9) and "e\u0301" become identical.
    return _lcs_len(unicodedata.normalize("NFKD", a), unicodedata.normalize("NFKD", b))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "unicodedata"}
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
    assert lcs_nfkd("caf\u00e9", "cafe\u0301") == 5
    assert lcs_nfkd("caf\u00e9", "cafe") == 4
    assert lcs_nfkd("\u00c5", "A") == 1
    assert lcs_nfkd("abc", "abc") == 3
    assert lcs_nfkd("", "a") == 0
    assert stdlib_only()
    print("44-ok OK")


if __name__ == "__main__":
    main()
