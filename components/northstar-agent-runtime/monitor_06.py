"""Trace sampling, Simulated.

Head-based samplers that decide keep/drop per trace: AlwaysOn,
AlwaysOff, Probability (deterministic via trace-id hash), and
RateLimiting (token bucket per second).

What this IS: cost control for span export -- only a fraction of
traces leave the host.

What this IS NOT:
* Not tail-based sampling -- decision is made at trace start.
"""

from __future__ import annotations

import ast
import hashlib
import time
from dataclasses import dataclass
from typing import Optional

#: Module version.
MONITOR_06_VERSION = "monitor-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-06.v1"


class SamplingError(Exception):
    """Fail-closed."""


def _check_trace_id(trace_id: str) -> None:
    if (
        not isinstance(trace_id, str)
        or len(trace_id) != 32
        or any(c not in "0123456789abcdef" for c in trace_id.lower())
    ):
        raise SamplingError("trace_id must be 32 hex chars")


class Sampler:
    """Base sampler."""

    def should_sample(self, trace_id: str) -> bool:
        raise NotImplementedError


class AlwaysOn(Sampler):
    def should_sample(self, trace_id: str) -> bool:
        _check_trace_id(trace_id)
        return True


class AlwaysOff(Sampler):
    def should_sample(self, trace_id: str) -> bool:
        _check_trace_id(trace_id)
        return False


class Probability(Sampler):
    """Deterministic: hashes trace_id so the decision is stable."""

    def __init__(self, rate: float) -> None:
        if not isinstance(rate, (int, float)) or not 0.0 <= rate <= 1.0:
            raise SamplingError("rate must be in [0,1]")
        self._rate = float(rate)

    def should_sample(self, trace_id: str) -> bool:
        _check_trace_id(trace_id)
        digest = hashlib.sha256(trace_id.encode()).digest()
        value = int.from_bytes(digest[:8], "big") / 2**64
        return value < self._rate


class RateLimiting(Sampler):
    """Keeps at most max_per_second traces (token bucket)."""

    def __init__(self, max_per_second: int) -> None:
        if not isinstance(max_per_second, int) or max_per_second <= 0:
            raise SamplingError("max_per_second must be positive int")
        self._max = max_per_second
        self._tokens = float(max_per_second)
        self._last_ns = time.time_ns()

    def should_sample(self, trace_id: str) -> bool:
        _check_trace_id(trace_id)
        now = time.time_ns()
        elapsed_s = (now - self._last_ns) / 1e9
        self._last_ns = now
        self._tokens = min(self._max, self._tokens + elapsed_s * self._max)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "pathlib", "time", "typing"}
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
    tid = "ab" * 16
    assert AlwaysOn().should_sample(tid) is True
    assert AlwaysOff().should_sample(tid) is False
    p0 = Probability(0.0)
    p1 = Probability(1.0)
    assert p0.should_sample(tid) is False
    assert p1.should_sample(tid) is True
    # Deterministic: same trace id -> same decision.
    phalf = Probability(0.5)
    assert phalf.should_sample(tid) == phalf.should_sample(tid)
    rl = RateLimiting(2)
    assert rl.should_sample(tid) is True
    assert rl.should_sample(tid) is True
    assert rl.should_sample(tid) is False  # bucket drained
    try:
        Probability(1.5)
        raise AssertionError("should raise")
    except SamplingError:
        pass
    try:
        AlwaysOn().should_sample("bad")
        raise AssertionError("should raise")
    except SamplingError:
        pass
    assert stdlib_only()
    print("monitor-06 OK: samplers, deterministic, fail-closed, stdlib")


if __name__ == "__main__":
    main()
