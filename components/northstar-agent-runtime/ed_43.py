"""Editex (phonetic edit distance)

Edit distance with sound-group-aware substitution costs.

What this IS: sub=0 same char, 1 same phonetic group, 2 otherwise; ins/del=1.

What this IS NOT:
* Soundex codes -- ed_33 encodes first, then plain Levenshtein.
* unit cost -- phonetically close letters are cheaper here.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_43_VERSION = "ed-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-43.v1"


_GROUPS = (
    "aeiouy", "bp", "ckq", "dt", "lr", "mn", "gj", "fpv", "szx", "csz", "wy",
)


def _group(ch: str):
    c = ch.lower()
    for i, g in enumerate(_GROUPS):
        if c in g:
            return i
    return None


def _sub_cost(x: str, y: str) -> float:
    if x == y:
        return 0.0
    gx, gy = _group(x), _group(y)
    if gx is not None and gx == gy:
        return 1.0
    return 2.0


def editex(a: str, b: str) -> float:
    """Editex phonetic edit distance."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    prev = [float(j) for j in range(n + 1)]
    for i in range(1, m + 1):
        cur = [float(i)] + [0.0] * n
        ai = a[i - 1]
        for j in range(1, n + 1):
            cur[j] = min(prev[j] + 1.0, cur[j - 1] + 1.0,
                         prev[j - 1] + _sub_cost(ai, b[j - 1]))
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
    assert editex("a", "e") == 1.0
    assert editex("a", "b") == 2.0
    assert editex("abc", "abc") == 0.0
    assert editex("p", "b") == 1.0
    assert editex("", "ab") == 2.0
    try:
        editex("a", 4)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("43-editex OK")


if __name__ == "__main__":
    main()
