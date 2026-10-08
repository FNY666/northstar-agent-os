"""Memoized Weighted Job Scheduling: memoization example.

Max profit from non-overlapping jobs sorted by end time: dp(i) = max(dp(i-1), profit[i] + dp(p(i))) where p(i) is the latest compatible job. The index cache gives O(n log n) with binary search, O(n^2) here.

What this IS: a real memoized weighted-interval scheduler expecting end-sorted jobs.
What this IS NOT: an unweighted activity selector; the host picks the variant.
"""

from __future__ import annotations

import ast

#: Module version.
MEMO_31_VERSION = "memo-weighted-job-scheduling.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.memo-weighted-job-scheduling.v1"


class MemoError(Exception):
    """Fail-closed."""


def job_schedule(jobs: tuple, i: int, _cache: dict | None = None) -> int:
    """Memoized max profit over jobs[0..i]; jobs must be end-sorted (start, end, profit)."""
    cache: dict = _cache if _cache is not None else {}
    if i in cache:
        return cache[i]
    if i < 0:
        cache[i] = 0
    else:
        p = -1
        for k in range(i - 1, -1, -1):
            if jobs[k][1] <= jobs[i][0]:
                p = k
                break
        cache[i] = max(job_schedule(jobs, i - 1, cache), jobs[i][2] + job_schedule(jobs, p, cache))
    return cache[i]

def test_job_schedule_example():
    jobs = ((1, 2, 50), (3, 5, 20), (6, 19, 100), (2, 100, 200))
    assert job_schedule(jobs, len(jobs) - 1) == 250


def test_job_schedule_single():
    assert job_schedule(((1, 2, 7),), 0) == 7


def test_job_schedule_none():
    assert job_schedule((), -1) == 0

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
    test_job_schedule_example()
    test_job_schedule_single()
    test_job_schedule_none()
    assert stdlib_only()
    print("memo-31 OK: weighted-job-scheduling")


if __name__ == "__main__":
    main()
