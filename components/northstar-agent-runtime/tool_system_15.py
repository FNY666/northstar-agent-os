"""Tool rate limiting: per-tool buckets, Simulated.

Token-bucket rate limiter per tool.  Each tool has capacity and
refill rate.  Calls consume tokens; when empty, calls are rejected
(fail-closed) rather than queued.

Time is injectable for tests.

What this IS: per-tool call-rate enforcement.

What this IS NOT:
* Not distributed -- in-process buckets.
* Rejected calls raise; no waiting.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

#: Module version.
TOOL_SYSTEM_15_VERSION = "tool-system-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-15.v1"


class ToolSystem15Error(Exception):
    """Fail-closed."""


class RateLimitExceeded(ToolSystem15Error):
    """Raised when a tool's bucket is empty."""


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    last: float


class RateLimiter:
    """Per-tool token buckets."""

    def __init__(self, clock: Optional[Callable[[], float]] = None) -> None:
        self._clock = clock or time.time
        self._buckets: Dict[str, _Bucket] = {}

    def configure(
        self, tool: str, capacity: float, refill_per_sec: float
    ) -> None:
        if not tool:
            raise ToolSystem15Error("tool required")
        if capacity <= 0 or refill_per_sec <= 0:
            raise ToolSystem15Error("capacity and refill must be positive")
        now = self._clock()
        self._buckets[tool] = _Bucket(
            capacity=capacity, refill_per_sec=refill_per_sec,
            tokens=capacity, last=now,
        )

    def _refill(self, bucket: _Bucket) -> None:
        now = self._clock()
        elapsed = max(0.0, now - bucket.last)
        bucket.tokens = min(
            bucket.capacity, bucket.tokens + elapsed * bucket.refill_per_sec
        )
        bucket.last = now

    def acquire(self, tool: str, tokens: float = 1.0) -> None:
        """Consume tokens; raises RateLimitExceeded if empty."""
        if tool not in self._buckets:
            raise ToolSystem15Error(f"unconfigured tool '{tool}'")
        if tokens <= 0:
            raise ToolSystem15Error("tokens must be positive")
        bucket = self._buckets[tool]
        self._refill(bucket)
        if bucket.tokens < tokens:
            raise RateLimitExceeded(
                f"tool '{tool}' rate limit exceeded"
            )
        bucket.tokens -= tokens

    def available(self, tool: str) -> float:
        if tool not in self._buckets:
            raise ToolSystem15Error(f"unconfigured tool '{tool}'")
        bucket = self._buckets[tool]
        self._refill(bucket)
        return bucket.tokens


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    now = {"t": 0.0}
    rl = RateLimiter(clock=lambda: now["t"])
    rl.configure("search", capacity=2, refill_per_sec=1.0)
    rl.acquire("search")
    rl.acquire("search")
    # Bucket empty.
    try:
        rl.acquire("search")
        raise AssertionError("should raise")
    except RateLimitExceeded:
        pass
    # Refill after 1.5s -> 1 token.
    now["t"] = 1.5
    assert rl.available("search") >= 1.0
    rl.acquire("search")
    # Unconfigured tool.
    try:
        rl.acquire("nope")
        raise AssertionError("should raise")
    except ToolSystem15Error:
        pass
    # Bad config.
    try:
        rl.configure("x", capacity=0, refill_per_sec=1)
        raise AssertionError("should raise")
    except ToolSystem15Error:
        pass
    assert stdlib_only()
    print("tool_system_15 OK: buckets, refill, reject")


if __name__ == "__main__":
    main()
