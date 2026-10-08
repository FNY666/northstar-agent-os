"""Tool canary deploys: staged percentage rollout, Simulated.

A CanaryDeployer rolls a tool version out through stages of increasing
traffic share (for example 10%, 25%, 50%, 100%).  Canary metrics
(errors/total) are recorded per stage; when a stage's error rate
exceeds the configured threshold the deploy auto-pauses (fail-safe
pause -- it does not roll back on its own).

Time is injectable for tests.

What this IS:
* A staged rollout state machine (Simulated).
* Per-stage error/total metrics with fail-safe auto-pause on
  error-rate threshold breach.

What this IS NOT:
* Not auto-rollback -- pause only.  Rollback is module 23's job.
* Not live traffic -- no real requests are routed.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

#: Module version.
TOOL_SYSTEM_21_VERSION = "tool-system-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-21.v1"


class ToolSystem21Error(Exception):
    """Fail-closed."""


class DeployPaused(ToolSystem21Error):
    """Raised when advancing a paused deploy."""


@dataclass
class _StageMetrics:
    total: int = 0
    errors: int = 0

    @property
    def error_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.errors / self.total


class CanaryDeployer:
    """Staged canary rollout for one tool version (Simulated)."""

    def __init__(
        self,
        tool: str,
        version: str,
        stages: Tuple[int, ...] = (10, 25, 50, 100),
        error_threshold: float = 0.05,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not tool:
            raise ToolSystem21Error("tool required")
        if not version:
            raise ToolSystem21Error("version required")
        if not stages:
            raise ToolSystem21Error("at least one stage required")
        for pct in stages:
            if not 0 < pct <= 100:
                raise ToolSystem21Error(f"bad stage pct {pct!r}")
        if not 0.0 <= error_threshold <= 1.0:
            raise ToolSystem21Error("error_threshold must be in [0, 1]")
        self.tool = tool
        self.version = version
        self.stages = list(stages)
        self.error_threshold = error_threshold
        self._clock = clock or time.time
        self._index = 0
        self._paused = False
        self._paused_at: Optional[float] = None
        self._metrics: Dict[int, _StageMetrics] = {
            i: _StageMetrics() for i in range(len(self.stages))
        }

    def current_stage(self) -> int:
        return self.stages[self._index]

    def complete(self) -> bool:
        return self._index == len(self.stages) - 1

    def advance(self) -> int:
        """Move to the next stage; returns the new stage pct."""
        if self._paused:
            raise DeployPaused("deploy is paused")
        if self.complete():
            raise ToolSystem21Error("already at final stage")
        self._index += 1
        return self.current_stage()

    def record(self, total: int, errors: int) -> None:
        """Record canary metrics for the current stage.

        Auto-pauses the deploy when the stage error rate exceeds the
        threshold.  This is a fail-safe pause, not a rollback.
        """
        if total < 0 or errors < 0 or errors > total:
            raise ToolSystem21Error("bad metrics: 0 <= errors <= total")
        m = self._metrics[self._index]
        m.total += total
        m.errors += errors
        if m.total > 0 and m.error_rate > self.error_threshold:
            self.pause()

    def pause(self) -> None:
        self._paused = True
        self._paused_at = self._clock()

    def resume(self) -> None:
        self._paused = False
        self._paused_at = None

    def error_rate(self) -> float:
        return self._metrics[self._index].error_rate

    def status(self) -> Dict[str, object]:
        m = self._metrics[self._index]
        return {
            "tool": self.tool,
            "version": self.version,
            "stage_index": self._index,
            "stage_pct": self.current_stage(),
            "stages": list(self.stages),
            "paused": self._paused,
            "paused_at": self._paused_at,
            "complete": self.complete(),
            "stage_total": m.total,
            "stage_errors": m.errors,
            "stage_error_rate": m.error_rate,
        }


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
    now = {"t": 0.0}
    d = CanaryDeployer(
        "search", "v2", stages=(10, 50, 100), error_threshold=0.1,
        clock=lambda: now["t"],
    )
    assert d.current_stage() == 10
    assert d.status()["paused"] is False
    d.record(100, 2)  # 2% error -- fine.
    assert not d.status()["paused"]
    assert d.advance() == 50
    d.record(100, 20)  # 20% error > 10% threshold -> auto-pause.
    assert d.status()["paused"] is True
    try:
        d.advance()
        raise AssertionError("should raise")
    except DeployPaused:
        pass
    d.resume()
    assert d.status()["paused"] is False
    assert d.advance() == 100
    assert d.complete()
    try:
        d.advance()
        raise AssertionError("should raise")
    except ToolSystem21Error:
        pass
    # Bad metrics.
    try:
        d.record(10, 20)
        raise AssertionError("should raise")
    except ToolSystem21Error:
        pass
    # Bad config.
    try:
        CanaryDeployer("", "v2")
        raise AssertionError("should raise")
    except ToolSystem21Error:
        pass
    assert stdlib_only()
    print("tool_system_21 OK: stages, metrics, auto-pause")


if __name__ == "__main__":
    main()
