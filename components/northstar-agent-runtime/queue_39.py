"""BoundedQueue: bounded non-blocking FIFO: try_put/try_get report success instead of waiting. IS: a fixed-capacity queue; try_put is False when full, try_get None when empty. IS NOT: a blocking producer/consumer queue with condition variables."""

from __future__ import annotations

import ast
from collections import deque
from typing import Any, Optional
VERSION = "queue-39.v1"

class BoundedQueue:
    """Fixed-capacity FIFO with non-blocking ``try_put``/``try_get``."""

    def __init__(self, capacity: int) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("capacity must be a positive int")
        self._cap = capacity
        self._q: deque = deque()

    def try_put(self, item: Any) -> bool:
        """Append ``item``; return False (dropping it) when full."""
        if len(self._q) >= self._cap:
            return False
        self._q.append(item)
        return True

    def try_get(self) -> Optional[Any]:
        """Remove and return the head item, or None when empty."""
        if not self._q:
            return None
        return self._q.popleft()

    def is_full(self) -> bool:
        return len(self._q) >= self._cap

    def is_empty(self) -> bool:
        return not self._q

    def __len__(self) -> int:
        return len(self._q)


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
    bq = BoundedQueue(2)
    assert bq.try_put("a") and bq.try_put("b")
    assert not bq.try_put("c") and bq.is_full()
    assert bq.try_get() == "a"
    assert bq.try_put("c") and len(bq) == 2
    assert bq.try_get() == "b" and bq.try_get() == "c"
    assert bq.try_get() is None and bq.is_empty()
    try:
        BoundedQueue(0)
    except ValueError:
        pass
    else:
        raise AssertionError("capacity 0 must raise ValueError")
    assert stdlib_only()
    print("queue-39 OK: non-blocking bounded queue")


if __name__ == "__main__":
    main()
