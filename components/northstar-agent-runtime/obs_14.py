"""obs_14: Continuous profiling (mock), Simulated.

Mock continuous profiler: start/stop lifecycle with configurable
interval, but does NOT actually sample in the background (no threads).
Records manual snapshots on demand.

Labeled mock so it is never mistaken for a real always-on profiler.

Fail-closed: invalid config raises.
Stdlib only.
"""

from __future__ import annotations

import ast
import time
from typing import Any, Dict, List

OBS14_VERSION = "obs-14.v1"
SCHEMA_PIN = "northstar.obs-14.v1"


class Obs14Error(Exception):
    """Fail-closed."""


class MockContinuousProfiler:
    """Mock: lifecycle only, snapshots on demand."""

    def __init__(self, interval_s: float = 60.0) -> None:
        if not isinstance(interval_s, (int, float)) or interval_s <= 0:
            raise Obs14Error("interval_s must be positive")
        self._interval = float(interval_s)
        self._running = False
        self._snapshots: List[Dict[str, Any]] = []
        self._started_at: float = 0.0

    def start(self) -> None:
        if self._running:
            raise Obs14Error("already running")
        self._running = True
        self._started_at = time.time()

    def stop(self) -> None:
        if not self._running:
            raise Obs14Error("not running")
        self._running = False

    def snapshot(self, label: str = "") -> Dict[str, Any]:
        """Take a manual snapshot (mock data)."""
        if not self._running:
            raise Obs14Error("profiler not running")
        if not isinstance(label, str):
            raise Obs14Error("label must be str")
        snap = {
            "label": label,
            "at": time.time(),
            "uptime_s": time.time() - self._started_at,
            # Mock: no real stack data.
            "stacks_sampled": 0,
            "mock": True,
        }
        self._snapshots.append(snap)
        return snap

    @property
    def running(self) -> bool:
        return self._running

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "time", "typing"}
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
    p = MockContinuousProfiler(interval_s=30)
    assert p.running is False
    p.start()
    s = p.snapshot("test")
    assert s["mock"] is True and p.snapshot_count == 1
    p.stop()
    assert p.running is False
    try:
        p.snapshot()
        raise AssertionError("should raise")
    except Obs14Error:
        pass
    try:
        MockContinuousProfiler(interval_s=0)
        raise AssertionError("should raise")
    except Obs14Error:
        pass
    assert stdlib_only()
    print("obs_14 OK")


if __name__ == "__main__":
    main()
