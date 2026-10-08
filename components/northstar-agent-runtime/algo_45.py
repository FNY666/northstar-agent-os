"""Levenshtein edit distance via dynamic programming.

Recurrence on prefixes a[:i], b[:j] with unit insert/delete/substitute cost:

    d[i][j] = min(d[i-1][j] + 1, d[i][j-1] + 1,
                  d[i-1][j-1] + (0 if a[i-1] == b[j-1] else 1))

Two-row table: time O(|a| * |b|), space O(min(|a|, |b|)).
"""

import ast
import sys
from pathlib import Path

ALGO_45_VERSION = "algo-45.v1"

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


def edit_distance(a: str, b: str) -> int:
    """Return the Levenshtein distance between ``a`` and ``b``."""
    if len(b) > len(a):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[len(b)]


def main() -> None:
    assert edit_distance("kitten", "sitting") == 3
    assert edit_distance("", "") == 0
    assert edit_distance("abc", "") == 3
    assert edit_distance("", "xyz") == 3
    assert edit_distance("abc", "abc") == 0
    assert edit_distance("a", "b") == 1
    assert edit_distance("flaw", "lawn") == 2
    assert edit_distance("sitting", "kitten") == 3  # symmetric
    assert stdlib_only()
    print("algo-45 OK")


if __name__ == "__main__":
    main()
