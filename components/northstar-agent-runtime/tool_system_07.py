"""Tool retries: exponential backoff, Simulated.

Retry a failing call with exponential backoff and jitter.
Only retries on designated retryable errors; fail-fast otherwise.
No real sleeping in tests -- backoff schedule is computed and exposed.

What this IS: retry policy with backoff schedule.

What this IS NOT:
* Not async -- synchronous retry loop.
* Sleep is injectable (tests use a no-op sleeper).
"""

from __future__ import annotations

import ast
import random
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple, Type

#: Module version.
TOOL_SYSTEM_07_VERSION = "tool-system-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-07.v1"


class ToolSystem07Error(Exception):
    """Fail-closed: exhausted retries raise this."""


@dataclass(frozen=True)
class RetryPolicy:
    """Retry configuration."""

    max_attempts: int = 3
    base_delay: float = 0.1
    max_delay: float = 10.0
    multiplier: float = 2.0
    retryable: Tuple[Type[BaseException], ...] = (Exception,)


def backoff_schedule(policy: RetryPolicy) -> List[float]:
    """Compute delays between attempts (no sleep)."""
    if policy.max_attempts < 1:
        raise ToolSystem07Error("max_attempts must be >= 1")
    delays: List[float] = []
    delay = policy.base_delay
    for _ in range(policy.max_attempts - 1):
        jitter = delay * random.uniform(0.8, 1.2)
        delays.append(min(jitter, policy.max_delay))
        delay = min(delay * policy.multiplier, policy.max_delay)
    return delays


def retry(
    fn: Callable[[], Any],
    policy: Optional[RetryPolicy] = None,
    sleeper: Optional[Callable[[float], None]] = None,
) -> Any:
    """Run fn with retries.  Returns fn() result or raises."""
    if policy is None:
        policy = RetryPolicy()
    delays = backoff_schedule(policy)
    last_error: Optional[BaseException] = None
    for attempt in range(policy.max_attempts):
        try:
            return fn()
        except policy.retryable as e:
            last_error = e
            if attempt < len(delays) and sleeper is not None:
                sleeper(delays[attempt])
        except BaseException:
            raise  # non-retryable: fail fast
    raise ToolSystem07Error(
        f"exhausted {policy.max_attempts} attempts: "
        f"{type(last_error).__name__ if last_error else '?'}"
    ) from last_error


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "random", "typing"}
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
    # Schedule shape.
    sched = backoff_schedule(RetryPolicy(max_attempts=4, base_delay=1.0))
    assert len(sched) == 3
    assert sched[0] < sched[1] < sched[2]  # exponential growth

    # Succeeds on 3rd try.
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("flaky")
        return "ok"

    slept: List[float] = []
    assert retry(flaky, sleeper=slept.append) == "ok"
    assert calls["n"] == 3
    assert len(slept) == 2

    # Exhausted.
    try:
        retry(lambda: (_ for _ in ()).throw(ValueError("x")),
              RetryPolicy(max_attempts=2))
        raise AssertionError("should raise")
    except ToolSystem07Error:
        pass

    # Non-retryable fails fast.
    try:
        retry(lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
              RetryPolicy(retryable=(ValueError,)))
        raise AssertionError("should raise")
    except KeyboardInterrupt:
        pass
    assert stdlib_only()
    print("tool_system_07 OK: backoff, retry, fail-fast")


if __name__ == "__main__":
    main()
