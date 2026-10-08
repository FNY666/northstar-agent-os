"""Retry helpers: exponential backoff, jitter, delay lists. What this IS: delay math for retry loops. What this IS NOT: not an executor (host sleeps)."""

from __future__ import annotations

import ast
import random

#: Module version.
UTIL_17_VERSION = "util-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-17.v1"


class RetryError(Exception):
    """Retry helper failure."""


def backoff_delay(attempt: int, base=1.0, cap=60.0, factor=2.0) -> float:
    if attempt < 0:
        raise RetryError("attempt must be >= 0")
    return min(cap, base * (factor ** attempt))


def with_jitter(delay: float, ratio=0.25, rng=None) -> float:
    if delay < 0:
        raise RetryError("delay must be >= 0")
    r = rng if rng is not None else random
    return max(0.0, delay * (1 + (r.random() * 2 - 1) * ratio))


def retry_delays(attempts: int, base=1.0, cap=60.0, factor=2.0):
    if attempts < 0:
        raise RetryError("attempts must be >= 0")
    return [backoff_delay(i, base, cap, factor) for i in range(attempts)]


def should_retry(exc: BaseException, retry_on=(Exception,)) -> bool:
    return isinstance(exc, retry_on)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 'random']
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
    assert backoff_delay(0) == 1.0
    assert backoff_delay(2) == 4.0
    assert backoff_delay(100) == 60.0
    v = with_jitter(10.0, 0.25, random.Random(0))
    assert 7.5 <= v <= 12.5
    assert retry_delays(3) == [1.0, 2.0, 4.0]
    assert should_retry(ValueError("x"), retry_on=(ValueError,)) is True
    print("retry helpers OK")


if __name__ == "__main__":
    main()
