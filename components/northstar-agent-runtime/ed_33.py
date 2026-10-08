"""Soundex-code edit distance

Levenshtein on Soundex phonetic codes instead of raw strings.

What this IS: Soundex encoding followed by unit Levenshtein on the 4-char codes.

What this IS NOT:
* raw-string Levenshtein -- phonetically equal names score 0.
* Editex -- ed_43 weights edits by sound groups directly.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_33_VERSION = "ed-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-33.v1"


_SOUNDEX_MAP = {
    "B": "1", "F": "1", "P": "1", "V": "1",
    "C": "2", "G": "2", "J": "2", "K": "2", "Q": "2", "S": "2", "X": "2", "Z": "2",
    "D": "3", "T": "3",
    "L": "4",
    "M": "5", "N": "5",
    "R": "6",
}


def soundex(s: str) -> str:
    """Classic American Soundex 4-character code."""
    if not isinstance(s, str):
        raise TypeError("input must be str")
    letters = [c for c in s.upper() if c.isalpha()]
    if not letters:
        return "0000"
    first = letters[0]
    digits = []
    prev = _SOUNDEX_MAP.get(first, "0")
    for c in letters[1:]:
        if c in "HW":
            continue  # ignored entirely; does not break runs
        d = _SOUNDEX_MAP.get(c, "0")
        if d != "0" and d != prev:
            digits.append(d)
        prev = d
    return (first + "".join(digits) + "000")[:4]


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


def soundex_distance(a: str, b: str) -> int:
    """Levenshtein distance between Soundex codes."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    return _lev(soundex(a), soundex(b))

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
    assert soundex("Robert") == soundex("Rupert")
    assert soundex_distance("Robert", "Rupert") == 0
    assert soundex("Ashcraft") == "A261"
    assert soundex_distance("Smith", "Smyth") == 0
    assert soundex_distance("abc", "xyz") > 0
    try:
        soundex_distance("a", 1)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("33-soundex OK")


if __name__ == "__main__":
    main()
