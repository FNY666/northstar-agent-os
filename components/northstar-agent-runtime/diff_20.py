"""Maximum CPU Load: difference array example.

Jobs (start, end, load) half-open; the maximum overlapping load via a weighted sparse difference sweep.

What this IS: a real weighted sweep for peak load, fail-closed on bad jobs
What this IS NOT: a timeline simulation per time unit
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_20_VERSION = "max-cpu-load.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-cpu-load.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_cpu_load(jobs: list) -> int:
    """jobs: list of (start, end, load). Returns peak overlapping load."""
    if not jobs:
        return 0
    diff = {}
    for s, e, load in jobs:
        if not (s < e) or load < 0:
            raise DiffError("bad job")
        diff[s] = diff.get(s, 0) + load
        diff[e] = diff.get(e, 0) - load
    cur = 0
    best = 0
    for k in sorted(diff):
        cur += diff[k]
        if cur > best:
            best = cur
    return best

def test_basic():
    assert max_cpu_load([(1, 4, 3), (2, 5, 4), (7, 9, 6)]) == 7


def test_single():
    assert max_cpu_load([(1, 2, 5)]) == 5


def test_empty():
    assert max_cpu_load([]) == 0


def test_bad():
    try:
        max_cpu_load([(3, 3, 1)])
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
    test_basic()
    test_single()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-20 OK: max-cpu-load")


if __name__ == "__main__":
    main()
