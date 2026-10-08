"""Backtracking: build word squares from a word list.

IS: finds every sequence of equal-length words where row i equals column
i for all i (a word square), using a prefix index to prune; words may be
reused across rows. IS NOT: a crossword or anagram tool - it checks the
square property only, knows no word meanings, and does not require the
words to be distinct.
"""

import ast
from typing import Dict, List, Optional

VERSION = "backtrack_28.v1"


def word_squares(words: List[str]) -> List[List[str]]:
    """All word squares buildable from words (all same length)."""
    if not words:
        return []
    n = len(words[0])
    words = [w for w in words if len(w) == n]
    prefix_map: Dict[str, List[str]] = {}
    for w in words:
        for i in range(n + 1):
            prefix_map.setdefault(w[:i], []).append(w)
    results: List[List[str]] = []

    def dfs(square: List[str]) -> None:
        if len(square) == n:
            results.append(list(square))
            return
        k = len(square)
        prefix = "".join(w[k] for w in square)
        for w in prefix_map.get(prefix, []):
            square.append(w)
            dfs(square)
            square.pop()

    for w in words:
        dfs([w])
    return results


def _is_square(square: List[str]) -> bool:
    n = len(square)
    return all(len(w) == n for w in square) and all(
        square[r][c] == square[c][r] for r in range(n) for c in range(n)
    )


def stdlib_only(path: Optional[str] = None) -> bool:
    """Parse this file with ast; True iff every import is stdlib-allowed."""
    allowed = {"typing", "dataclasses", "itertools", "ast"}
    with open(path or __file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod and mod not in allowed:
                return False
    return True


def main() -> None:
    assert stdlib_only()
    classic = ["area", "lead", "wall", "lady", "ball"]
    squares = word_squares(classic)
    assert ["wall", "area", "lead", "lady"] in squares
    assert all(_is_square(sq) for sq in squares)
    assert all(all(w in classic for w in sq) for sq in squares)
    assert word_squares(["ab", "ba"]) == [["ab", "ba"], ["ba", "ab"]]
    assert word_squares(["a"]) == [["a"]]
    assert word_squares([]) == []
    print("backtrack_28 OK")


if __name__ == "__main__":
    main()
