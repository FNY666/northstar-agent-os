"""Backtracking: palindrome partitioning.

IS: enumerate *all* ways to split string ``s`` into substrings that are
each palindromes (LeetCode 131). The recursion tries every cut position;
only palindromic prefixes are extended, so every emitted partition is
valid and every valid partition is emitted exactly once.

IS NOT: longest-palindromic-substring / shortest-palindrome problems,
nor a single "best" partition - this enumerates the whole partition
space, exponentially many in the worst case (e.g. "aaaa").

Self-test harness: run ``python backtrack_13.py``.
"""

from typing import List

VERSION = "backtrack_13.v1"

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


def is_palindrome(s: str) -> bool:
    return s == s[::-1]


def partition(s: str) -> List[List[str]]:
    """All palindrome partitions of s."""
    results: List[List[str]] = []

    def dfs(start: int, path: List[str]) -> None:
        if start == len(s):
            results.append(path.copy())
            return
        for end in range(start + 1, len(s) + 1):
            piece = s[start:end]
            if is_palindrome(piece):
                path.append(piece)
                dfs(end, path)
                path.pop()

    dfs(0, [])
    return results


def main() -> None:
    # Two ways to cut "aab".
    assert partition("aab") == [["a", "a", "b"], ["aa", "b"]]
    # Single char.
    assert partition("a") == [["a"]]
    # "efe": [e,f,e] and [efe].
    got = partition("efe")
    assert sorted(got) == [["e", "f", "e"], ["efe"]], got
    # Every piece of every partition is a palindrome, and pieces join to s.
    for part in partition("abccba"):
        assert "".join(part) == "abccba"
        assert all(is_palindrome(p) for p in part)
    # "abccba" has 4 partitions: [a,b,c,c,b,a], [a,b,cc,b,a],
    # [a,bccb,a], [abccba].
    assert len(partition("abccba")) == 4
    assert stdlib_only() is True
    print("backtrack_13 OK")


if __name__ == "__main__":
    main()
