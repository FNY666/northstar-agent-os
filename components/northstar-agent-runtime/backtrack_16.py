"""Backtracking: word break - find all segmentations.

IS: given string ``s`` and a dictionary, enumerate every segmentation of
``s`` into space-joined dictionary words (LeetCode 140). A memo of which
suffix positions admit *any* completion prunes dead branches so the
enumeration never walks into a doomed suffix twice.

IS NOT: the boolean word-break decision problem (LeetCode 139) alone -
though its memo logic is reused internally as the pruning oracle; nor
ranking segmentations - all completions are emitted, unordered.

Self-test harness: run ``python backtrack_16.py``.
"""

from typing import Dict, List, Set

VERSION = "backtrack_16.v1"

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


def word_break_all(s: str, word_dict: Set[str]) -> List[str]:
    """All space-joined segmentations of s using words from word_dict."""
    words = set(word_dict)
    memo: Dict[int, bool] = {}

    def completable(start: int) -> bool:
        """Memoized oracle: can s[start:] be segmented at all?"""
        if start == len(s):
            return True
        if start in memo:
            return memo[start]
        ok = False
        for end in range(start + 1, len(s) + 1):
            if s[start:end] in words and completable(end):
                ok = True
                break
        memo[start] = ok
        return ok

    results: List[str] = []

    def dfs(start: int, path: List[str]) -> None:
        if start == len(s):
            results.append(" ".join(path))
            return
        for end in range(start + 1, len(s) + 1):
            if s[start:end] in words and completable(end):
                path.append(s[start:end])
                dfs(end, path)
                path.pop()

    dfs(0, [])
    return results


def main() -> None:
    words = {"cat", "cats", "and", "sand", "dog"}
    # Two segmentations.
    got = word_break_all("catsanddog", words)
    assert sorted(got) == ["cat sand dog", "cats and dog"], got
    # Single segmentation.
    assert word_break_all("leetcode", {"leet", "code"}) == ["leet code"]
    # Unsegmentable -> empty.
    assert word_break_all("catsandog", words) == []
    # Empty string: the degenerate single empty segmentation.
    assert word_break_all("", words) == [""]
    # Every emitted segmentation rejoins to s using dict words only.
    d = {"a", "aa", "aaa"}
    for seg in word_break_all("aaaa", d):
        assert seg.replace(" ", "") == "aaaa"
        assert all(w in d for w in seg.split(" "))
    assert stdlib_only() is True
    print("backtrack_16 OK")


if __name__ == "__main__":
    main()
