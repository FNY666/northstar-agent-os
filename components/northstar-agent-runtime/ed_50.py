"""Hybrid similarity (normalized Levenshtein + Jaro-Winkler)

Mean of complement-normalized-Levenshtein and Jaro-Winkler.

What this IS: 0.5*(1 - norm_lev) + 0.5*jw in [0, 1]; 1.0 means identical.

What this IS NOT:
* a single metric -- it blends an edit and a Jaro-family score.
* a distance -- higher means more similar.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_50_VERSION = "ed-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-50.v1"


def _lev(a: str, b: str) -> int:
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def _jaro(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
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
        return 0.0
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
    return (matches / la + matches / lb + (matches - t) / matches) / 3.0


def _jaro_winkler(a: str, b: str, p: float = 0.1) -> float:
    j = _jaro(a, b)
    prefix = 0
    for c1, c2 in zip(a, b):
        if c1 == c2 and prefix < 4:
            prefix += 1
        else:
            break
    return j + prefix * p * (1.0 - j)


def hybrid_similarity(a: str, b: str) -> float:
    """0.5*(1 - normalized Levenshtein) + 0.5*Jaro-Winkler."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not a and not b:
        lev_sim = 1.0
    else:
        lev_sim = 1.0 - _lev(a, b) / max(len(a), len(b))
    return 0.5 * lev_sim + 0.5 * _jaro_winkler(a, b)

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
    assert hybrid_similarity("abc", "abc") == 1.0
    assert hybrid_similarity("", "") == 1.0
    s = hybrid_similarity("kitten", "sitting")
    assert 0.0 <= s <= 1.0
    assert hybrid_similarity("abc", "abc") > hybrid_similarity("abc", "xyz")
    try:
        hybrid_similarity("a", 3)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("50-hybrid OK")


if __name__ == "__main__":
    main()
