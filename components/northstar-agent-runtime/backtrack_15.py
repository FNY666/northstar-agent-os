"""Backtracking: letter combinations of a phone number.

IS: given a digit string (2-9), enumerate every string formed by picking
one letter per digit from the classic telephone keypad mapping
(LeetCode 17). One digit consumed per recursion depth; the empty input
yields the empty list, not [""].

IS NOT: predictive-text ranking, T9 disambiguation, or handling 0/1 -
digits outside 2-9 have no letters and are left unmapped by design.

Self-test harness: run ``python backtrack_15.py``.
"""

from typing import Dict, List

VERSION = "backtrack_15.v1"

_ALLOWED_IMPORTS = frozenset({"typing", "dataclasses", "itertools", "ast"})


def stdlib_only() -> bool:
    """Parse this file with ``ast``; True only if every import comes from the
    allowed stdlib set."""
    import ast

    with open(__file__, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=__file__)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0:
                return False
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return False
    return True


KEYPAD: Dict[str, str] = {
    "2": "abc",
    "3": "def",
    "4": "ghi",
    "5": "jkl",
    "6": "mno",
    "7": "pqrs",
    "8": "tuv",
    "9": "wxyz",
}


def letter_combinations(digits: str) -> List[str]:
    """All letter strings for the given phone digits."""
    if not digits:
        return []
    results: List[str] = []

    def dfs(i: int, path: List[str]) -> None:
        if i == len(digits):
            results.append("".join(path))
            return
        for ch in KEYPAD[digits[i]]:
            path.append(ch)
            dfs(i + 1, path)
            path.pop()

    dfs(0, [])
    return results


def main() -> None:
    # 2x3 = 9 combos for "23".
    got = letter_combinations("23")
    assert got == [
        "ad", "ae", "af",
        "bd", "be", "bf",
        "cd", "ce", "cf",
    ], got
    # Empty input -> empty list.
    assert letter_combinations("") == []
    # Single digit.
    assert letter_combinations("2") == ["a", "b", "c"]
    # 7 maps to 4 letters: 3*4 = 12 combos, each length 2.
    got = letter_combinations("27")
    assert len(got) == 12
    assert all(len(c) == 2 for c in got)
    assert all(c[0] in "abc" and c[1] in "pqrs" for c in got)
    assert stdlib_only() is True
    print("backtrack_15 OK")


if __name__ == "__main__":
    main()
