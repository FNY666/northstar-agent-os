"""Daily quota enforcement (input defense), Simulated

What this IS: Per-user daily quotas on tool calls and estimated tokens. Hard stop when the day's budget is spent.

What this IS NOT:
* Day boundary uses an injectable date provider (UTC default).
* In-memory only; production persists counters.
"""

from __future__ import annotations

import datetime

#: Module version.
MODULE_VERSION = "input-defense-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-24.v1"

ALLOWED_IMPORTS = frozenset({'datetime', 'pathlib', '__future__', 'ast', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


class DailyQuota:
    """Daily per-user quotas for calls and tokens."""

    def __init__(self, max_calls_per_day=1000, max_tokens_per_day=100000,
                 date_fn=None):
        if max_calls_per_day <= 0 or max_tokens_per_day <= 0:
            raise InputDefenseError("quotas must be positive")
        self.max_calls = max_calls_per_day
        self.max_tokens = max_tokens_per_day
        self._date_fn = date_fn or (
            lambda: __import__("datetime").date.today().isoformat()
        )
        self._usage = {}  # (user_id, day) -> {"calls": int, "tokens": int}

    def _key(self, user_id):
        if not user_id:
            raise InputDefenseError("user_id required")
        return (user_id, self._date_fn())

    def consume(self, user_id, tokens=0):
        """Consume one call plus tokens. Returns True if within quota."""
        if tokens < 0:
            raise InputDefenseError("tokens must be non-negative")
        key = self._key(user_id)
        usage = self._usage.get(key, {"calls": 0, "tokens": 0})
        if usage["calls"] + 1 > self.max_calls:
            return False
        if usage["tokens"] + tokens > self.max_tokens:
            return False
        usage["calls"] += 1
        usage["tokens"] += tokens
        self._usage[key] = usage
        return True

    def usage(self, user_id):
        """Current usage for today."""
        return dict(self._usage.get(self._key(user_id), {"calls": 0, "tokens": 0}))



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
    day = ["2026-10-09"]
    q = DailyQuota(max_calls_per_day=2, max_tokens_per_day=100,
                   date_fn=lambda: day[0])
    assert q.consume("u", tokens=10) is True
    assert q.consume("u", tokens=10) is True
    assert q.consume("u", tokens=10) is False  # call quota spent
    assert q.usage("u") == {"calls": 2, "tokens": 20}
    day[0] = "2026-10-10"  # new day resets
    assert q.consume("u", tokens=10) is True
    try:
        q.consume("", 0)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-24.v1 OK")


if __name__ == "__main__":
    main()
