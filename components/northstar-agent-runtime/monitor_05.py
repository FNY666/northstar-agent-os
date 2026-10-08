"""Log aggregation (mock), Simulated.

In-memory log aggregator: structured LogEntry records with level,
service, message, and fields. Query by level/service/time window,
count rates, and detect error bursts.

What this IS: a local stand-in for an ELK/Loki pipeline during
development and tests.

What this IS NOT:
* Not persistent -- memory only. Host ships to real storage.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_05_VERSION = "monitor-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-05.v1"

_VALID_LEVELS = {"debug", "info", "warning", "error", "critical"}


class LogAggError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class LogEntry:
    ts_ns: int
    level: str
    service: str
    message: str
    fields: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.level not in _VALID_LEVELS:
            raise LogAggError(f"bad level {self.level!r}")
        if not self.service or not self.message:
            raise LogAggError("service and message required")


class Aggregator:
    """In-memory log store with query support."""

    def __init__(self, max_entries: int = 100000) -> None:
        if max_entries <= 0:
            raise LogAggError("max_entries must be positive")
        self._max = max_entries
        self._entries: List[LogEntry] = []

    def log(
        self,
        level: str,
        service: str,
        message: str,
        fields: Optional[Dict[str, Any]] = None,
    ) -> LogEntry:
        entry = LogEntry(
            ts_ns=time.time_ns(),
            level=level,
            service=service,
            message=message,
            fields=fields or {},
        )
        self._entries.append(entry)
        if len(self._entries) > self._max:
            del self._entries[: len(self._entries) - self._max]
        return entry

    def query(
        self,
        level: Optional[str] = None,
        service: Optional[str] = None,
        since_ns: Optional[int] = None,
        contains: Optional[str] = None,
        limit: int = 1000,
    ) -> List[LogEntry]:
        if level is not None and level not in _VALID_LEVELS:
            raise LogAggError(f"bad level {level!r}")
        if limit <= 0:
            raise LogAggError("limit must be positive")
        out: List[LogEntry] = []
        for e in reversed(self._entries):
            if level and e.level != level:
                continue
            if service and e.service != service:
                continue
            if since_ns and e.ts_ns < since_ns:
                continue
            if contains and contains not in e.message:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def error_burst(
        self, service: str, window_ns: int, threshold: int
    ) -> bool:
        """True if >= threshold error/critical entries in window."""
        if threshold <= 0:
            raise LogAggError("threshold must be positive")
        now = time.time_ns()
        count = sum(
            1
            for e in self._entries
            if e.service == service
            and e.level in ("error", "critical")
            and now - e.ts_ns <= window_ns
        )
        return count >= threshold


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
    """Self-check."""
    agg = Aggregator(max_entries=10)
    agg.log("info", "gate", "decision allow", {"gate": "authorize"})
    agg.log("error", "gate", "decision deny spike")
    agg.log("error", "gate", "decision deny spike")
    assert len(agg.query(level="error")) == 2
    assert len(agg.query(service="gate", contains="spike")) == 2
    assert agg.error_burst("gate", window_ns=10**12, threshold=2) is True
    assert agg.error_burst("gate", window_ns=10**12, threshold=5) is False
    for _ in range(12):
        agg.log("info", "x", "filler")
    assert len(agg._entries) == 10  # ring bound
    try:
        agg.log("bogus", "s", "m")
        raise AssertionError("should raise")
    except LogAggError:
        pass
    try:
        agg.query(level="bogus")
        raise AssertionError("should raise")
    except LogAggError:
        pass
    assert stdlib_only()
    print("monitor-05 OK: aggregate, query, burst, fail-closed, stdlib")


if __name__ == "__main__":
    main()
