"""Hamming distance

Position-wise mismatch count for equal-length strings.

What this IS: the Hamming distance: substitutions only, strings must be equal length.

What this IS NOT:
* an edit distance -- insertions and deletions are not allowed.
* defined for unequal lengths -- that raises ValueError.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_03_VERSION = "ed-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-03.v1"


def hamming(a: str, b: str) -> int:
    """Hamming distance; equal-length strings only."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if len(a) != len(b):
        raise ValueError("Hamming distance requires equal-length strings")
    return sum(c1 != c2 for c1, c2 in zip(a, b))

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
    assert hamming("karolin", "kathrin") == 3
    assert hamming("", "") == 0
    assert hamming("abc", "abc") == 0
    assert hamming("1011101", "1001001") == 2
    try:
        hamming("abc", "ab")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("03-hamming OK")


if __name__ == "__main__":
    main()
