"""Maximum Concurrent Events: difference array example.

Events (start, end) half-open; the peak number of concurrent events via a sparse difference sweep.

What this IS: a real peak-concurrency sweep, fail-closed on bad events
What this IS NOT: checking concurrency only at event starts
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_45_VERSION = "max-concurrent-events.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-max-concurrent-events.v1"


class DiffError(Exception):
    """Fail-closed."""


def max_concurrent(events: list) -> int:
    """events: list of (start, end) half-open. Returns peak concurrency."""
    if not events:
        return 0
    d = {}
    for s, e in events:
        if not (s < e):
            raise DiffError("need start < end")
        d[s] = d.get(s, 0) + 1
        d[e] = d.get(e, 0) - 1
    cur = 0
    best = 0
    for k in sorted(d):
        cur += d[k]
        if cur > best:
            best = cur
    return best

def test_basic():
    assert max_concurrent([(1, 4), (2, 5), (3, 6), (7, 8)]) == 3


def test_single():
    assert max_concurrent([(1, 2)]) == 1


def test_empty():
    assert max_concurrent([]) == 0


def test_bad():
    try:
        max_concurrent([(2, 2)])
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
    print("diff-45 OK: max-concurrent-events")


if __name__ == "__main__":
    main()
