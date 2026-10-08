"""SlidingWindowRateLimiter: sliding-window rate limiter: at most max_calls calls per window seconds. IS: a call gate; allow() is True iff fewer than max_calls timestamps are in-window. IS NOT: a token-bucket limiter or a distributed limiter."""

from __future__ import annotations

import ast
from collections import deque
VERSION = "queue-19.v1"

class SlidingWindowRateLimiter:
    """Allow at most ``max_calls`` calls in any ``window``-second span."""

    def __init__(self, max_calls: int, window: float) -> None:
        if isinstance(max_calls, bool) or not isinstance(max_calls, int) or max_calls <= 0:
            raise ValueError("max_calls must be a positive int")
        if isinstance(window, bool) or not isinstance(window, (int, float)) or window <= 0:
            raise ValueError("window must be a positive number")
        self._max = max_calls
        self._window = float(window)
        self._hits: deque = deque()

    def allow(self, timestamp: float) -> bool:
        """Return True and record the call if it fits in the window."""
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise ValueError("timestamp must be a real number")
        ts = float(timestamp)
        while self._hits and self._hits[0] <= ts - self._window:
            self._hits.popleft()
        if len(self._hits) >= self._max:
            return False
        self._hits.append(ts)
        return True


def stdlib_only() -> bool:
    """AST-check: every import in this file resolves to the standard library."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing", "collections"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    rl = SlidingWindowRateLimiter(3, 10.0)
    assert rl.allow(0) and rl.allow(1) and rl.allow(2)
    assert not rl.allow(3)  # 4th call inside the window
    assert rl.allow(11)  # t=0 and t=1 aged out; t=2 still counts
    assert rl.allow(11.5)  # window (1.5, 11.5] holds t=2, 11 -> still room
    assert rl.allow(12)  # window (2, 12] holds 11, 11.5 -> still room
    assert not rl.allow(12.5)  # window (2.5, 12.5] holds 11, 11.5, 12 -> full
    assert rl.allow(25)  # window fully slid
    rl2 = SlidingWindowRateLimiter(2, 5.0)
    assert rl2.allow(0) and rl2.allow(1)
    assert not rl2.allow(2)
    assert rl2.allow(5)  # t=0 aged out exactly at the boundary
    try:
        rl.allow("now")
    except ValueError:
        pass
    else:
        raise AssertionError("non-numeric timestamp must raise ValueError")
    for bad in ((0, 10.0), (3, 0), ("3", 10.0)):
        try:
            SlidingWindowRateLimiter(*bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"args {bad!r} must raise ValueError")
    assert stdlib_only()
    print("queue-19 OK: sliding-window rate limiter")


if __name__ == "__main__":
    main()
