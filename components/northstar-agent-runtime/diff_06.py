"""Maximum Population Year: difference array example.

LeetCode 1854: logs (birth, death); death exclusive; the year with the maximum living population via a sparse difference sweep.

What this IS: a real sparse sweep returning the earliest max year, fail-closed on bad logs
What this IS NOT: a year-by-year simulation over the whole range
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_06_VERSION = "max-population-year.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-population-year.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_population_year(logs: list) -> int:
    """logs: list of (birth, death). Returns earliest year with max population."""
    if not logs:
        raise DiffError("no logs")
    diff = {}
    for b, d in logs:
        if not (b < d):
            raise DiffError("birth must be < death")
        diff[b] = diff.get(b, 0) + 1
        diff[d] = diff.get(d, 0) - 1
    best_year = None
    best = 0
    cur = 0
    for y in sorted(diff):
        cur += diff[y]
        if cur > best:
            best = cur
            best_year = y
    return best_year

def test_example():
    assert max_population_year([[1993, 1999], [2000, 2010]]) == 1993


def test_overlap():
    assert max_population_year([[1950, 1961], [1960, 1971], [1970, 1981]]) == 1960


def test_single():
    assert max_population_year([[2000, 2005]]) == 2000


def test_bad():
    for bad in (lambda: max_population_year([]),
                lambda: max_population_year([[2005, 2000]])):
        try:
            bad()
        except DiffError:
            continue
        raise AssertionError("expected DiffError")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_example()
    test_overlap()
    test_single()
    test_bad()
    assert stdlib_only()
    print("diff-06 OK: max-population-year")


if __name__ == "__main__":
    main()
