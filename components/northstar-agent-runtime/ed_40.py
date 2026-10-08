"""Jaro-Winkler with custom prefix scale

Jaro-Winkler where the prefix scale p and boost threshold are parameters.

What this IS: the Winkler boost applied only above the similarity threshold.

What this IS NOT:
* fixed p=0.1 -- ed_06 pins the standard scale.
* unbounded -- output stays in [0, 1].
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_40_VERSION = "ed-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-40.v1"


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


def jaro_winkler_params(
    a: str, b: str, p: float = 0.1, threshold: float = 0.7
) -> float:
    """Jaro-Winkler with custom prefix scale and boost threshold."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if not 0.0 <= p <= 0.25:
        raise ValueError("p must be in [0, 0.25]")
    j = _jaro(a, b)
    if j < threshold:
        return j
    prefix = 0
    for c1, c2 in zip(a, b):
        if c1 == c2 and prefix < 4:
            prefix += 1
        else:
            break
    return min(1.0, j + prefix * p * (1.0 - j))

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
    assert abs(jaro_winkler_params("MARTHA", "MARHTA") - 0.9611111) < 1e-6
    assert jaro_winkler_params("abc", "abc") == 1.0
    assert jaro_winkler_params("abc", "xyz", threshold=0.99) == _jaro("abc", "xyz")
    assert jaro_winkler_params("dixon", "dicksonx", p=0.0) == _jaro("dixon", "dicksonx")
    try:
        jaro_winkler_params("a", "b", p=0.5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("40-jw-params OK")


if __name__ == "__main__":
    main()
