"""Jaro similarity

Jaro string similarity in [0, 1]; higher means more similar.

What this IS: the Jaro similarity with the standard matching window.

What this IS NOT:
* Jaro-Winkler -- ed_06 adds the prefix boost.
* a distance -- this is a similarity (1.0 = identical).
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_05_VERSION = "ed-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-05.v1"


def jaro(a: str, b: str) -> float:
    """Jaro similarity in [0, 1]."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
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
    assert abs(jaro("MARTHA", "MARHTA") - 0.9444444) < 1e-6
    assert jaro("abc", "abc") == 1.0
    assert jaro("", "abc") == 0.0
    assert jaro("abc", "def") == 0.0
    assert 0.0 <= jaro("dixon", "dicksonx") <= 1.0
    try:
        jaro("a", 5)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("05-jaro OK")


if __name__ == "__main__":
    main()
