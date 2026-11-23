"""Small retry helper used by the offline coding benchmark."""
from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def retry(
    operation: Callable[[], T],
    *,
    max_attempts: int = 3,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> T:
    """Run ``operation`` until it succeeds or the attempt budget is exhausted."""
    last_error: Exception | None = None
    for _ in range(max_attempts + 1):
        try:
            return operation()
        except exceptions as error:
            last_error = error
    assert last_error is not None
    raise last_error
