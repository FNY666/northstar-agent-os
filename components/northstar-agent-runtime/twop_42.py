"""longest_substring_at_most_k_distinct (two-pointer), longest substring with <= k distinct chars. IS: a sliding window with a frequency map shrinking the left edge when distinct count exceeds k. IS NOT: a brute-force O(n^2) substring enumerator."""
from __future__ import annotations

import ast

VERSION = "twop-42.v1"


def longest_substring_at_most_k_distinct(s: str, k: int) -> int:
    """Return the length of the longest substring of s with at most k distinct chars."""
    if not isinstance(s, str):
        raise ValueError("s must be a string")
    if isinstance(k, bool) or not isinstance(k, int):
        raise ValueError("k must be an int")
    if k < 0:
        raise ValueError("k must be non-negative")
    counts: dict[str, int] = {}
    left = 0
    best = 0
    for right, ch in enumerate(s):
        counts[ch] = counts.get(ch, 0) + 1
        while len(counts) > k:
            counts[s[left]] -= 1
            if counts[s[left]] == 0:
                del counts[s[left]]
            left += 1
        window = right - left + 1
        if window > best:
            best = window
    return best


def stdlib_only() -> bool:
    """AST-parse this file; return False if any import outside the allowed set appears."""
    import pathlib
    src = pathlib.Path(__file__).read_text()
    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert longest_substring_at_most_k_distinct("eceba", 2) == 3
    assert longest_substring_at_most_k_distinct("aa", 1) == 2
    assert longest_substring_at_most_k_distinct("abc", 0) == 0  # edge: k=0
    assert longest_substring_at_most_k_distinct("", 3) == 0
    assert longest_substring_at_most_k_distinct("abaccc", 2) == 4
    try:
        longest_substring_at_most_k_distinct("abc", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for negative k")
    assert stdlib_only()
    print("longest_substring_at_most_k_distinct OK")


if __name__ == "__main__":
    main()
