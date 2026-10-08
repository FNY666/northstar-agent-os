"""Longest common substring length

Length of the longest contiguous block shared by both strings.

What this IS: the longest common *contiguous* substring via DP.

What this IS NOT:
* LCS -- ed_08 allows gaps between matched characters.
* an alignment -- only the length is returned.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_13_VERSION = "ed-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-13.v1"


def longest_common_substring(a: str, b: str) -> int:
    """Length of the longest common contiguous substring."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    best = 0
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best

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
    assert longest_common_substring("ABABC", "BABCA") == 4
    assert longest_common_substring("abc", "def") == 0
    assert longest_common_substring("abc", "abc") == 3
    assert longest_common_substring("", "abc") == 0
    try:
        longest_common_substring("a", 3)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("13-lcsubstr OK")


if __name__ == "__main__":
    main()
