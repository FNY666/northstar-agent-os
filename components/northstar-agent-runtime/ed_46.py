"""Bitap approximate substring search

Myers' approximate search: pattern end positions within k errors.

What this IS: bit-parallel approximate matching returning text end indices.

What this IS NOT:
* exact search -- up to k errors are tolerated.
* Sellers -- ed_14 returns the min distance, not positions.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_46_VERSION = "ed-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-46.v1"


def bitap_search(pattern: str, text: str, k: int) -> List[int]:
    """End positions in text where pattern matches within k errors."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        raise TypeError("inputs must be str")
    if not isinstance(k, int) or k < 0:
        raise ValueError("k must be a non-negative int")
    m = len(pattern)
    if m == 0:
        return list(range(len(text) + 1))
    peq: Dict[str, int] = {}
    for i, ch in enumerate(pattern):
        peq[ch] = peq.get(ch, 0) | (1 << i)
    mask = (1 << m) - 1
    pv = mask
    mv = 0
    score = m
    top = 1 << (m - 1)
    out: List[int] = []
    for i, ch in enumerate(text):
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
        if score <= k:
            out.append(i)
    return out

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
    assert bitap_search("abc", "xxabcxx", 0) == [4]
    assert bitap_search("abd", "xxabcxx", 1) == [4]
    assert bitap_search("abc", "xxabcxx", 1) == [3, 4, 5]
    assert bitap_search("zzz", "abc", 0) == []
    try:
        bitap_search("a", "b", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    assert stdlib_only()
    print("46-bitap OK")


if __name__ == "__main__":
    main()
