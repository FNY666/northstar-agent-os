"""Longest common subsequence length

Length of the longest common subsequence (not necessarily contiguous).

What this IS: the LCS length via two-row DP, O(m*n) time and O(n) space.

What this IS NOT:
* longest common substring -- ed_13 requires contiguity.
* an edit distance -- ed_04 derives one from this.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_08_VERSION = "ed-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-08.v1"


def lcs_length(a: str, b: str) -> int:
    """Length of the longest common subsequence."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[n]

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
    assert lcs_length("ABCDGH", "AEDFHR") == 3
    assert lcs_length("", "abc") == 0
    assert lcs_length("abc", "abc") == 3
    assert lcs_length("kitten", "sitting") == 4
    try:
        lcs_length("a", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("08-lcs OK")


if __name__ == "__main__":
    main()
