"""MRA (match rating approach) comparator

Simplified match-rating-approach name comparison returning bool.

What this IS: vowel-stripped, deduped codes compared within a small threshold.

What this IS NOT:
* a distance -- this answers match/no-match.
* Soundex -- different code recipe and threshold logic.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_44_VERSION = "ed-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-44.v1"


def _mra_code(s: str) -> str:
    letters = [c for c in s.upper() if c.isalpha()]
    if not letters:
        return ""
    first = letters[0]
    rest = [c for c in letters[1:] if c not in "AEIOU"]
    code = first + "".join(rest)
    out = [code[0]]
    for c in code[1:]:
        if c != out[-1]:
            out.append(c)
    return "".join(out)


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


def mra_match(a: str, b: str, threshold: int = 2) -> bool:
    """Simplified match rating approach: True when codes are close."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    if threshold < 0:
        raise ValueError("threshold must be >= 0")
    return _lev(_mra_code(a), _mra_code(b)) <= threshold

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
    assert mra_match("Smith", "Smyth") is True
    assert mra_match("Smith", "Jones") is False
    assert mra_match("Catherine", "Kathryn") is True
    assert _mra_code("Smith") == "SMTH"
    try:
        mra_match("a", "b", threshold=-1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("44-mra OK")


if __name__ == "__main__":
    main()
