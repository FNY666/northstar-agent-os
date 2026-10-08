"""intv_29: Maximum profit job scheduling (job_scheduling).

Sort by end; DP with binary search for the last compatible job.

Time complexity: O(n log n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys

import bisect
INTV_29 = "intv-29.v1"


def job_scheduling(start, end, profit):
    """Max profit subset of non-overlapping jobs."""
    jobs = sorted(zip(start, end, profit), key=lambda j: j[1])
    ends = [j[1] for j in jobs]
    dp = [0] * (len(jobs) + 1)
    for i, (s, e, p) in enumerate(jobs, 1):
        j = bisect.bisect_right(ends, s, 0, i - 1)
        dp[i] = max(dp[i - 1], dp[j] + p)
    return dp[-1]

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert job_scheduling([1, 2, 3, 3], [3, 4, 5, 6], [50, 10, 40, 70]) == 120
    assert job_scheduling([1, 2, 3, 4, 6], [3, 5, 10, 6, 9], [20, 20, 100, 70, 60]) == 150
    assert job_scheduling([1, 1, 1], [2, 3, 4], [5, 6, 4]) == 6
    assert job_scheduling([], [], []) == 0
    assert job_scheduling([1], [2], [10]) == 10
    assert stdlib_only()
    print("intv_29 OK")


if __name__ == "__main__":
    main()
