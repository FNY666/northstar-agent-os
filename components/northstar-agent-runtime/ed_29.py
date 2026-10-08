"""Jaro similarity (detailed)

Jaro similarity plus the raw match/transposition counts.

What this IS: Jaro returning (similarity, matches, transpositions).

What this IS NOT:
* plain Jaro -- ed_05 returns only the similarity.
* Jaro-Winkler -- no prefix boost here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_29_VERSION = "ed-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-29.v1"


def jaro_detailed(a: str, b: str) -> Tuple[float, int, int]:
    """Jaro similarity with (similarity, matches, transpositions)."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if a == b:
        return (1.0, len(a), 0)
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return (0.0, 0, 0)
    match_dist = max(la, lb) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    a_match = [False] * la
    b_match = [False] * lb
    matches = 0
    for i in range(la):
        lo = max(0, i - match_dist)
        hi = min(lb, i + match_dist + 1)
        for j in range(lo, hi):
            if not b_match[j] and a[i] == b[j]:
                a_match[i] = True
                b_match[j] = True
                matches += 1
                break
    if matches == 0:
        return (0.0, 0, 0)
    t = 0
    k = 0
    for i in range(la):
        if a_match[i]:
            while not b_match[k]:
                k += 1
            if a[i] != b[k]:
                t += 1
            k += 1
    t //= 2
    sim = (matches / la + matches / lb + (matches - t) / matches) / 3.0
    return (sim, matches, t)

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
    sim, m, t = jaro_detailed("MARTHA", "MARHTA")
    assert abs(sim - 0.9444444) < 1e-6
    assert m == 6 and t == 1
    assert jaro_detailed("abc", "abc") == (1.0, 3, 0)
    assert jaro_detailed("", "abc") == (0.0, 0, 0)
    assert jaro_detailed("abc", "def")[0] == 0.0
    try:
        jaro_detailed("a", 3)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("29-jaro-detailed OK")


if __name__ == "__main__":
    main()
