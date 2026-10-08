"""Longest common subsequence (LCS) via dynamic programming.

Recurrence on prefixes a[:i], b[:j]:

    L[i][j] = L[i-1][j-1] + 1        if a[i-1] == b[j-1]
    L[i][j] = max(L[i-1][j], L[i][j-1]) otherwise

``lcs`` backtracks through the table to return one longest common
subsequence string (not just its length); ``lcs_length`` returns the length
using a space-optimised two-row table. Time O(|a| * |b|); space O(|a| * |b|)
for ``lcs``, O(min(|a|, |b|)) for ``lcs_length``.
"""

import ast
import sys
from pathlib import Path

ALGO_43_VERSION = "algo-43.v1"

STDLIB_USED = frozenset({"ast", "pathlib", "sys"})


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


def _lcs_table(a: str, b: str):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        ai = a[i - 1]
        row, prev = dp[i], dp[i - 1]
        for j in range(1, n + 1):
            if ai == b[j - 1]:
                row[j] = prev[j - 1] + 1
            else:
                row[j] = prev[j] if prev[j] >= row[j - 1] else row[j - 1]
    return dp


def lcs(a: str, b: str) -> str:
    """Return one longest common subsequence of ``a`` and ``b`` as a string."""
    dp = _lcs_table(a, b)
    i, j = len(a), len(b)
    chars = []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            chars.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return "".join(reversed(chars))


def lcs_length(a: str, b: str) -> int:
    """Return the length of the longest common subsequence of ``a`` and ``b``."""
    if len(b) > len(a):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    for ca in a:
        cur = [0] * (len(b) + 1)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[len(b)]


def _is_subsequence(sub: str, s: str) -> bool:
    it = iter(s)
    return all(c in it for c in sub)


def main() -> None:
    assert lcs_length("ABCBDAB", "BDCABA") == 4
    got = lcs("ABCBDAB", "BDCABA")
    assert len(got) == 4
    assert _is_subsequence(got, "ABCBDAB") and _is_subsequence(got, "BDCABA")
    assert lcs("abc", "abc") == "abc"
    assert lcs("abc", "xyz") == ""
    assert lcs("", "abc") == "" and lcs("abc", "") == ""
    assert lcs_length("", "") == 0
    assert lcs_length("AGGTAB", "GXTXAYB") == 4
    assert stdlib_only()
    print("algo-43 OK")


if __name__ == "__main__":
    main()
