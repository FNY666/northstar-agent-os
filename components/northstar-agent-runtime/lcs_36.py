"""Fuzzy match via LCS ratio

What this IS: True when the Dice LCS ratio reaches a threshold, with early termination.

What this IS NOT:
* exact threshold on length -- see lcs_21.
* the raw ratio -- see lcs_17.
"""

from __future__ import annotations

import ast
import math
#: Module version.
LCS_36_VERSION = "lcs-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-36.v1"


def _lcs_len(x: str, y: str) -> int:
    prev = [0] * (len(y) + 1)
    for cx in x:
        cur = [0] * (len(y) + 1)
        for j, cy in enumerate(y, 1):
            cur[j] = prev[j - 1] + 1 if cx == cy else (prev[j] if prev[j] >= cur[j - 1] else cur[j - 1])
        prev = cur
    return prev[len(y)]


def fuzzy_match(a: str, b: str, threshold: float) -> bool:
    # Need LCS >= threshold*(m+n)/2; prune with the lcs_21 decision test.
    m, n = len(a), len(b)
    if not a and not b:
        return True
    need = math.ceil(threshold * (m + n) / 2.0 - 1e-9)
    if need <= 0:
        return True
    if need > min(m, n):
        return False
    prev = [0] * (n + 1)
    for i in range(1, m + 1):
        cur = [0] * (n + 1)
        ai = a[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        rem = m - i
        bound = 0
        for j in range(n + 1):
            tail = rem if rem < n - j else n - j
            cand = cur[j] + tail
            if cand > bound:
                bound = cand
        if bound < need:
            return False
        prev = cur
    return prev[n] >= need

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "math"}
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
    assert fuzzy_match("abcde", "ace", 0.7) is True
    assert fuzzy_match("abcde", "ace", 0.8) is False
    assert fuzzy_match("abc", "abc", 1.0) is True
    assert fuzzy_match("", "", 0.5) is True
    assert fuzzy_match("abc", "def", 0.1) is False
    assert stdlib_only()
    print("36-ok OK")


if __name__ == "__main__":
    main()
