"""Myers bit-parallel Levenshtein

Myers' O(ND) bit-parallel edit distance using Python big ints.

What this IS: the bit-parallel algorithm; exact, fast for moderate lengths.

What this IS NOT:
* the textbook DP -- ed_01 uses the full matrix.
* an approximation -- this returns the exact distance.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_11_VERSION = "ed-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-11.v1"


def myers_levenshtein(a: str, b: str) -> int:
    """Exact Levenshtein via Myers' bit-parallel algorithm."""
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    # Use the shorter string as the pattern.
    if len(a) > len(b):
        a, b = b, a
    m = len(a)
    if m == 0:
        return len(b)
    peq: Dict[str, int] = {}
    for i, ch in enumerate(a):
        peq[ch] = peq.get(ch, 0) | (1 << i)
    mask = (1 << m) - 1
    pv = mask
    mv = 0
    score = m
    top = 1 << (m - 1)
    for ch in b:
        eq = peq.get(ch, 0)
        xv = eq | mv
        xh = (((eq & pv) + pv) ^ pv) | eq
        ph = (mv | ~(xh | pv)) & mask
        mh = (pv & xh) & mask
        if ph & top:
            score += 1
        elif mh & top:
            score -= 1
        ph = ((ph << 1) | 1) & mask
        mh = (mh << 1) & mask
        pv = (mh | ~(xv | ph)) & mask
        mv = (ph & xv) & mask
    return score

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
    assert myers_levenshtein("kitten", "sitting") == 3
    assert myers_levenshtein("", "abc") == 3
    assert myers_levenshtein("abc", "abc") == 0
    assert myers_levenshtein("flaw", "lawn") == 2
    assert myers_levenshtein("saturday", "sunday") == 3
    try:
        myers_levenshtein("a", 9)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("11-myers OK")


if __name__ == "__main__":
    main()
