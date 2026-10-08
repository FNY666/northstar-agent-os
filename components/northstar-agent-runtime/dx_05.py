"""DX-05: Watch mode (mock), Simulated.

Runs a task callable whenever a (mock) file-change event arrives,
with debounce: rapid successive events collapse into one run.
Task exceptions are captured into the run record -- the watcher
never dies because a task failed.

Fail-closed: misconfigured debounce or missing task raises at
construction/run time, never silently no-ops.

What this IS: event -> debounced task execution with a run log.
What this IS NOT: not a real filesystem watcher.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
DX05_WATCH_VERSION = "dx-watch.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-watch.v1"


class WatchError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class WatchRun:
    seq: int
    trigger: str
    ok: bool
    result: Any = None
    error: str = ""
    at: float = 0.0


class MockWatch:
    """Debounced task runner over simulated file events."""

    def __init__(
        self,
        task: Callable[[str], Any],
        *,
        debounce_s: float = 0.2,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not callable(task):
            raise WatchError("task must be callable")
        if debounce_s < 0:
            raise WatchError("debounce_s must be >= 0")
        self._task = task
        self._debounce = debounce_s
        self._clock = clock or time.time
        self._runs: List[WatchRun] = []
        self._last_run_at: Optional[float] = None
        self._pending: Optional[str] = None

    def notify(self, path: str) -> None:
        """Simulate a file-change event."""
        if not path:
            raise WatchError("path required")
        self._pending = path

    def flush(self) -> List[WatchRun]:
        """Run the pending task if debounce elapsed.  Returns new runs."""
        if self._pending is None:
            return []
        now = self._clock()
        if self._last_run_at is not None and (now - self._last_run_at) < self._debounce:
            return []  # still debouncing; keep pending
        trigger = self._pending
        self._pending = None
        seq = len(self._runs)
        try:
            result = self._task(trigger)
            run = WatchRun(seq=seq, trigger=trigger, ok=True, result=result, at=now)
        except Exception as e:
            run = WatchRun(seq=seq, trigger=trigger, ok=False,
                           error=f"{type(e).__name__}", at=now)
        self._runs.append(run)
        self._last_run_at = now
        return [run]

    @property
    def runs(self) -> List[WatchRun]:
        return list(self._runs)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    now = [1000.0]
    w = MockWatch(lambda p: f"built {p}", debounce_s=10.0, clock=lambda: now[0])
    w.notify("a.py")
    w.notify("b.py")  # collapses: only latest trigger runs
    runs = w.flush()
    assert len(runs) == 1 and runs[0].trigger == "b.py" and runs[0].ok
    # still within debounce: no new run
    w.notify("c.py")
    assert w.flush() == []
    now[0] += 11.0
    runs = w.flush()
    assert len(runs) == 1 and runs[0].trigger == "c.py"
    # failing task is captured, watcher survives
    def boom(p: str) -> Any:
        raise RuntimeError("x")
    w2 = MockWatch(boom, debounce_s=0.0)
    w2.notify("z.py")
    runs = w2.flush()
    assert runs[0].ok is False and runs[0].error == "RuntimeError"
    try:
        MockWatch("not-callable")  # type: ignore
        raise AssertionError("should raise")
    except WatchError:
        pass
    assert stdlib_only()
    print("dx_05 OK: debounce, run log, task-failure captured")


if __name__ == "__main__":
    main()
