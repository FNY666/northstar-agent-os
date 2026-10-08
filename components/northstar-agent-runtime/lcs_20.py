"""LCS reconstruction (Hirschberg linear space)

What this IS: one LCS string in O(m*n) time but O(min(m,n)) space via divide and conquer.

What this IS NOT:
* the full-table backtrack -- see lcs_03 for the simpler version.
* length-only linear space -- see lcs_02.
"""

from __future__ import annotations

import ast

#: Module version.
LCS_20_VERSION = "lcs-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-20.v1"


def _last_row(x: str, y: str):
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev


def _is_subseq(s: str, t: str) -> bool:
    it = iter(t)
    return all(c in it for c in s)


def hirschberg(a: str, b: str) -> str:
    # Split a in half; find the split point of b maximizing left+right LCS.
    if not a:
        return ""
    if len(a) == 1:
        return a if a in b else ""
    i = len(a) // 2
    left = _last_row(a[:i], b)
    right = _last_row(a[i:][::-1], b[::-1])
    n = len(b)
    best_k, best_v = 0, -1
    for k in range(n + 1):
        v = left[k] + right[n - k]
        if v > best_v:
            best_v, best_k = v, k
    return hirschberg(a[:i], b[:best_k]) + hirschberg(a[i:], b[best_k:])

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
    assert hirschberg("abcde", "ace") == "ace"
    assert hirschberg("abc", "def") == ""
    s = hirschberg("AGGTAB", "GXTXAYB")
    assert len(s) == 4 and _is_subseq(s, "AGGTAB") and _is_subseq(s, "GXTXAYB")
    assert hirschberg("", "abc") == ""
    assert hirschberg("abc", "abc") == "abc"
    assert stdlib_only()
    print("20-ok OK")


if __name__ == "__main__":
    main()
