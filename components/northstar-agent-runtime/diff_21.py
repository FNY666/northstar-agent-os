"""Active Users Timeline Stats: difference array example.

Login/logout events; peak concurrency plus the full (time, active) timeline via a sparse difference sweep.

What this IS: a real event sweep returning peak and timeline, fail-closed on bad events
What this IS NOT: scanning every integer time unit
"""

from __future__ import annotations

import ast

#: Module version.
DIFF_21_VERSION = "active-users-timeline.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.diff-active-users-timeline.v1"


class DiffError(Exception):
    """Fail-closed."""


def timeline_stats(events: list) -> tuple:
    """events: list of (login, logout). Returns (peak, [(time, active)])."""
    diff = {}
    for login, logout in events:
        if not (login < logout):
            raise DiffError("need login < logout")
        diff[login] = diff.get(login, 0) + 1
        diff[logout] = diff.get(logout, 0) - 1
    cur = 0
    peak = 0
    timeline = []
    for t in sorted(diff):
        cur += diff[t]
        timeline.append((t, cur))
        if cur > peak:
            peak = cur
    return peak, timeline

def test_peak():
    peak, _ = timeline_stats([(1, 4), (2, 5), (3, 6)])
    assert peak == 3


def test_timeline():
    peak, tl = timeline_stats([(1, 2)])
    assert peak == 1
    assert tl == [(1, 1), (2, 0)]


def test_empty():
    assert timeline_stats([]) == (0, [])


def test_bad():
    try:
        timeline_stats([(4, 4)])
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
    test_peak()
    test_timeline()
    test_empty()
    test_bad()
    assert stdlib_only()
    print("diff-21 OK: active-users-timeline")


if __name__ == "__main__":
    main()
