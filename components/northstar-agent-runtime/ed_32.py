"""Keyboard-weighted Levenshtein

Substitutions between adjacent QWERTY keys cost less.

What this IS: unit Levenshtein with sub cost 0.5 for neighboring keys, 1.0 otherwise.

What this IS NOT:
* plain unit cost -- ed_01 charges 1 for every substitution.
* phonetic -- ed_33/ed_43 use sound groups instead.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_32_VERSION = "ed-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-32.v1"


_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


def _key_pos(ch: str):
    c = ch.lower()
    for r, row in enumerate(_ROWS):
        i = row.find(c)
        if i >= 0:
            return (r, i)
    return None


def _sub_cost(x: str, y: str) -> float:
    if x == y:
        return 0.0
    px, py = _key_pos(x), _key_pos(y)
    if px is not None and py is not None:
        if abs(px[0] - py[0]) + abs(px[1] - py[1]) == 1:
            return 0.5
    return 1.0


def keyboard_levenshtein(a: str, b: str) -> float:
    """Levenshtein with QWERTY-adjacency-weighted substitutions."""
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
    assert keyboard_levenshtein("abc", "abc") == 0.0
    assert keyboard_levenshtein("a", "s") == 0.5
    assert keyboard_levenshtein("a", "p") == 1.0
    assert keyboard_levenshtein("a", "s") < keyboard_levenshtein("a", "p")
    assert keyboard_levenshtein("", "ab") == 2.0
    try:
        keyboard_levenshtein("a", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("32-keyboard OK")


if __name__ == "__main__":
    main()
