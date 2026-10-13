"""Per-user rate limiting, token bucket (input defense), Simulated

What this IS: Token-bucket rate limiter keyed by user id. Bounds request rate to blunt brute-force and flooding.

What this IS NOT:
* In-memory only; production needs shared state.
* Clock is injectable for deterministic tests.
"""

from __future__ import annotations

import time

#: Module version.
MODULE_VERSION = "input-defense-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-22.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'time', 'ast', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


class TokenBucket:
    """Token bucket keyed by user id."""

    def __init__(self, capacity=10, refill_per_sec=1.0, time_fn=None):
        if capacity <= 0:
            raise InputDefenseError("capacity must be positive")
        if refill_per_sec < 0:
            raise InputDefenseError("refill_per_sec must be non-negative")
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._time = time_fn or __import__("time").time
        self._buckets = {}

    def _refill(self, user_id, now):
        tokens, last = self._buckets.get(user_id, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        return tokens, now

    def allow(self, user_id, cost=1):
        """Consume cost tokens. Returns True if allowed."""
        if not user_id:
            raise InputDefenseError("user_id required")
        if cost <= 0:
            raise InputDefenseError("cost must be positive")
        now = self._time()
        tokens, last = self._refill(user_id, now)
        if tokens < cost:
            self._buckets[user_id] = (tokens, last)
            return False
        self._buckets[user_id] = (tokens - cost, last)
        return True

    def remaining(self, user_id):
        """Current token count (refilled to now)."""
        now = self._time()
        tokens, _ = self._refill(user_id, now)
        return tokens



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    clock = [0.0]
    b = TokenBucket(capacity=2, refill_per_sec=1.0, time_fn=lambda: clock[0])
    assert b.allow("u1") is True
    assert b.allow("u1") is True
    assert b.allow("u1") is False  # exhausted
    clock[0] = 2.0  # refill 2 tokens
    assert b.allow("u1") is True
    assert b.remaining("u2") == 2.0
    try:
        b.allow("", 1)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-22.v1 OK")


if __name__ == "__main__":
    main()
