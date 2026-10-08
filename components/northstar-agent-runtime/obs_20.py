"""obs_20: Uptime checks (mock data format), Simulated.

UptimeTracker keeps a registry of named targets and their recorded
probe results (ok / not-ok at a timestamp).  uptime_pct(name, window_s)
computes the success percentage over samples whose timestamps fall
inside the trailing window relative to now.  Mock: no probes run;
results are recorded by the caller (e.g. from the synthetic checks).

Fail-closed: recording for unknown targets, duplicate targets, and
bad timestamps or windows raise.
Stdlib only.
"""

from __future__ import annotations

import ast
import time
from typing import Dict, List, Tuple

OBS20_VERSION = "obs-20.v1"
SCHEMA_PIN = "northstar.obs-20.v1"


class Obs20Error(Exception):
    """Fail-closed."""


def _check_ts(ts: object) -> float:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise Obs20Error("ts must be a number")
    v = float(ts)
    if v < 0:
        raise Obs20Error("ts must be non-negative")
    return v


class UptimeTracker:
    """Registry of targets plus recorded up/down probe samples."""

    def __init__(self) -> None:
        self._samples: Dict[str, List[Tuple[float, bool]]] = {}

    def add_target(self, name: str) -> None:
        """Register a target.  Duplicate names raise."""
        if not isinstance(name, str) or not name.strip():
            raise Obs20Error("name must be non-empty str")
        key = name.strip()
        if key in self._samples:
            raise Obs20Error(f"target '{key}' already registered")
        self._samples[key] = []

    def record(self, name: str, ok: bool, ts: float) -> None:
        """Record one probe result.  Unknown targets raise."""
        if not isinstance(name, str) or not name.strip():
            raise Obs20Error("name must be non-empty str")
        key = name.strip()
        if key not in self._samples:
            raise Obs20Error(f"unknown target '{key}'")
        if not isinstance(ok, bool):
            raise Obs20Error("ok must be bool")
        self._samples[key].append((_check_ts(ts), ok))

    def uptime_pct(self, name: str, window_s: float) -> float:
        """Success % over samples inside the trailing window_s seconds."""
        if not isinstance(name, str) or not name.strip():
            raise Obs20Error("name must be non-empty str")
        key = name.strip()
        if key not in self._samples:
            raise Obs20Error(f"unknown target '{key}'")
        if isinstance(window_s, bool) or not isinstance(window_s, (int, float)):
            raise Obs20Error("window_s must be a number")
        window = float(window_s)
        if window <= 0:
            raise Obs20Error("window_s must be positive")
        cutoff = time.time() - window
        in_window = [ok for ts, ok in self._samples[key] if ts >= cutoff]
        if not in_window:
            raise Obs20Error(f"no samples for '{key}' in window")
        return 100.0 * sum(1 for ok in in_window if ok) / len(in_window)

    def targets(self) -> List[str]:
        """Sorted list of registered target names."""
        return sorted(self._samples.keys())


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "time"}
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
    t = UptimeTracker()
    t.add_target("api")
    t.add_target("web")
    assert t.targets() == ["api", "web"]
    now = time.time()
    t.record("api", True, now - 60)
    t.record("api", True, now - 30)
    t.record("api", False, now - 10)
    t.record("api", True, now - 3600)  # outside the window
    assert t.uptime_pct("api", 300) == 200.0 / 3
    try:
        t.uptime_pct("web", 300)
        raise AssertionError("should raise")
    except Obs20Error:
        pass
    try:
        t.record("nope", True, now)
        raise AssertionError("should raise")
    except Obs20Error:
        pass
    try:
        t.add_target("api")
        raise AssertionError("should raise")
    except Obs20Error:
        pass
    try:
        t.uptime_pct("api", 0)
        raise AssertionError("should raise")
    except Obs20Error:
        pass
    try:
        t.record("api", "yes", now)  # type: ignore
        raise AssertionError("should raise")
    except Obs20Error:
        pass
    assert stdlib_only()
    print("obs_20 OK")


if __name__ == "__main__":
    main()
