"""Word break via dynamic programming.

``word_break``: dp[i] is True when prefix s[:i] segments into dictionary
words:

    dp[0] = True
    dp[i] = OR over j<i of dp[j] and s[j:i] in words

``word_break_all`` keeps a predecessor pointer on the first reachable split
and backtracks to return one valid segmentation list, or None when no
segmentation exists. Time O(n^2 * w) with w the max word length cost folded
into substring hashing, space O(n).
"""

import ast
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Set

ALGO_50_VERSION = "algo-50.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys", "typing"})


def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every imported top-level module
    is one this module actually uses from the standard library."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    stdlib_names = set(sys.stdlib_module_names)
    for name in sorted(imported):
        assert name in stdlib_names, "non-stdlib import: %s" % name
        assert name in STDLIB_USED, "imported but unused module: %s" % name
    assert set(STDLIB_USED) == imported, (
        "import drift: declared %s vs found %s"
        % (sorted(STDLIB_USED), sorted(imported))
    )
    return True


def word_break(s: str, word_dict: Sequence[str]) -> bool:
    """Return True when ``s`` segments into words from ``word_dict``."""
    words: Set[str] = set(word_dict)
    n = len(s)
    dp: List[bool] = [False] * (n + 1)
    dp[0] = True
    for i in range(1, n + 1):
        dp[i] = any(dp[j] and s[j:i] in words for j in range(i))
    return dp[n]


def word_break_all(s: str, word_dict: Sequence[str]) -> Optional[List[str]]:
    """Return one valid segmentation of ``s`` as a word list, or None."""
    words: Set[str] = set(word_dict)
    n = len(s)
    dp: List[bool] = [False] * (n + 1)
    prev: List[int] = [-1] * (n + 1)
    dp[0] = True
    for i in range(1, n + 1):
        for j in range(i):
            if dp[j] and s[j:i] in words:
                dp[i] = True
                prev[i] = j
                break
    if not dp[n]:
        return None
    parts: List[str] = []
    i = n
    while i > 0:
        j = prev[i]
        parts.append(s[j:i])
        i = j
    parts.reverse()
    return parts


def main() -> None:
    assert word_break("leetcode", ["leet", "code"]) is True
    assert word_break_all("leetcode", ["leet", "code"]) == ["leet", "code"]
    assert word_break("catsandog", ["cats", "dog", "sand", "and", "cat"]) is False
    assert word_break_all("catsandog", ["cats", "dog", "sand", "and", "cat"]) is None
    assert word_break("", []) is True
    assert word_break_all("", []) == []
    assert word_break("applepenapple", ["apple", "pen"]) is True
    seg = word_break_all("applepenapple", ["apple", "pen"])
    assert seg is not None and "".join(seg) == "applepenapple"
    assert stdlib_only()
    print("algo-50 OK")


if __name__ == "__main__":
    main()
