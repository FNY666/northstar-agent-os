"""Tool bulkheads: isolation, Simulated.

Bulkheads isolate tool pools: each tool (or group) gets its own
bounded worker pool.  One slow/failing tool cannot starve others.

What this IS: fault isolation via separate executors.

What this IS NOT:
* Threads only -- no process isolation.
"""

from __future__ import annotations

import ast
import concurrent.futures
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Module version.
TOOL_SYSTEM_14_VERSION = "tool-system-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-14.v1"


class ToolSystem14Error(Exception):
    """Fail-closed."""


class BulkheadFullError(ToolSystem14Error):
    """Raised when a bulkhead's queue is full."""


@dataclass
class Bulkhead:
    """Isolated pool for one tool group."""

    name: str
    max_workers: int = 4
    queue_size: int = 16
    _pool: Optional[concurrent.futures.ThreadPoolExecutor] = field(
        default=None, repr=False, compare=False
    )
    _sem: Optional[threading.Semaphore] = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.max_workers < 1:
            raise ToolSystem14Error("max_workers must be >= 1")
        if self.queue_size < 1:
            raise ToolSystem14Error("queue_size must be >= 1")
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=f"bulkhead-{self.name}",
        )
        self._sem = threading.Semaphore(self.queue_size)

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any):
        """Submit work; raises BulkheadFullError if queue is full."""
        if not self._sem.acquire(blocking=False):
            raise BulkheadFullError(f"bulkhead '{self.name}' queue full")
        fut = self._pool.submit(fn, *args, **kwargs)

        def _release(done):
            self._sem.release()

        fut.add_done_callback(_release)
        return fut

    def shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True)


class BulkheadManager:
    """Manages named bulkheads."""

    def __init__(self) -> None:
        self._heads: Dict[str, Bulkhead] = {}

    def add(self, bulkhead: Bulkhead) -> None:
        if bulkhead.name in self._heads:
            raise ToolSystem14Error(f"duplicate bulkhead '{bulkhead.name}'")
        self._heads[bulkhead.name] = bulkhead

    def submit(
        self, bulkhead_name: str, fn: Callable[..., Any],
        *args: Any, **kwargs: Any,
    ):
        if bulkhead_name not in self._heads:
            raise ToolSystem14Error(f"unknown bulkhead '{bulkhead_name}'")
        return self._heads[bulkhead_name].submit(fn, *args, **kwargs)

    def shutdown_all(self) -> None:
        for head in self._heads.values():
            head.shutdown()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "concurrent", "dataclasses",
        "pathlib", "threading", "typing",
    }
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
    mgr = BulkheadManager()
    mgr.add(Bulkhead("fast", max_workers=2, queue_size=4))
    mgr.add(Bulkhead("slow", max_workers=1, queue_size=2))
    try:
        # Fast bulkhead works independently of slow.
        f1 = mgr.submit("fast", lambda: 1)
        f2 = mgr.submit("fast", lambda: 2)
        assert f1.result(timeout=5) == 1
        assert f2.result(timeout=5) == 2
        # Queue-full raises.
        heads: List = []
        try:
            for _ in range(10):
                heads.append(mgr.submit("slow", lambda: 1))
            raise AssertionError("should raise")
        except BulkheadFullError:
            pass
        # Unknown bulkhead.
        try:
            mgr.submit("nope", lambda: 1)
            raise AssertionError("should raise")
        except ToolSystem14Error:
            pass
    finally:
        mgr.shutdown_all()
    assert stdlib_only()
    print("tool_system_14 OK: isolation, queue-full, unknown")


if __name__ == "__main__":
    main()
