"""Minimum Railway Platforms: difference array example.

Classic: arrivals/departures with inclusive overlap; minimum platforms via a sparse difference sweep.

What this IS: a real inclusive sweep for min platforms, fail-closed on bad input
What this IS NOT: a minute-by-minute platform simulation
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_22_VERSION = "min-platforms.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-min-platforms.v1"


class DiffError(Exception):
    """Fail-closed."""


def min_platforms(arrivals: list, departures: list) -> int:
    """Equal-length lists; a train needs a platform while arrival <= t <= departure."""
    if len(arrivals) != len(departures):
        raise DiffError("length mismatch")
    diff = {}
    for a, d in zip(arrivals, departures):
        if a > d:
            raise DiffError("arrival must be <= departure")
        diff[a] = diff.get(a, 0) + 1
        diff[d + 1] = diff.get(d + 1, 0) - 1
    cur = 0
    best = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > best:
            best = cur
    return best

def test_classic():
    arr = [900, 940, 950, 1100, 1500, 1800]
    dep = [910, 1200, 1120, 1130, 1900, 2000]
    assert min_platforms(arr, dep) == 3


def test_single():
    assert min_platforms([100], [200]) == 1


def test_empty():
    assert min_platforms([], []) == 0


def test_mismatch():
    try:
        min_platforms([100], [200, 300])
    except DiffError:
        return
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
    test_classic()
    test_single()
    test_empty()
    test_mismatch()
    assert stdlib_only()
    print("diff-22 OK: min-platforms")


if __name__ == "__main__":
    main()
