"""Jaro-Winkler similarity

Jaro similarity with a boost for shared prefixes.

What this IS: Jaro-Winkler with the standard prefix scale p=0.1, max prefix 4.

What this IS NOT:
* plain Jaro -- ed_05 has no prefix boost.
* a distance -- this is a similarity in [0, 1].
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_06_VERSION = "ed-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-06.v1"


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


def jaro_winkler(a: str, b: str, p: float = 0.1) -> float:
    """Jaro-Winkler similarity in [0, 1]."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    j = _jaro(a, b)
    prefix = 0
    for c1, c2 in zip(a, b):
        if c1 == c2 and prefix < 4:
            prefix += 1
        else:
            break
    return j + prefix * p * (1.0 - j)

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
    assert abs(jaro_winkler("MARTHA", "MARHTA") - 0.9611111) < 1e-6
    assert jaro_winkler("abc", "abc") == 1.0
    assert jaro_winkler("", "abc") == 0.0
    assert jaro_winkler("dixon", "dicksonx") >= _jaro("dixon", "dicksonx")
    try:
        jaro_winkler("a", None)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("06-jaro-winkler OK")


if __name__ == "__main__":
    main()
