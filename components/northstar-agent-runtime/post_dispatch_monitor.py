"""Post-dispatch invariant monitoring (Orrery Gate 6 style).

The permission gate checks BEFORE dispatch. This module monitors AFTER:
it consumes the audit/decision record stream and watches for emergent
pathologies in a sliding window -- error-rate spikes, state oscillation
(retry loops), and quota leaks. When an invariant breaks, it triggers
HALT (stop the run, require human review).

This is the gate the composition rules don't cover: pre-dispatch checks
can't see what happens after the tool runs. A tool that succeeds 100
times then starts failing 50% is a signal no pre-check can produce.

Design:
- Sliding window over the last N records (default 100)
- Three invariants:
  1. Error rate: if > threshold (default 20%) of recent calls failed, HALT
  2. Oscillation: if the same (tool, args) is retried > max_retries (default 5)
     with alternating outcomes, HALT (retry loop)
  3. Quota: if call rate exceeds max_calls_per_window, HALT (runaway)
- Verdicts: OK, WARN (approaching threshold), HALT (invariant broken)
- Stateless per-window: no persistence, recomputed from the record stream
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

MonitorVerdict = Literal["OK", "WARN", "HALT"]


@dataclass
class PostDispatchMonitor:
    """Sliding-window invariant monitor over post-dispatch records."""

    window_size: int = 100
    max_error_rate: float = 0.20
    max_retries: int = 5
    max_calls_per_window: int = 1000
    warn_error_rate: float = 0.10

    _window: deque[dict[str, Any]] = field(default_factory=deque, repr=False)
    _halted: bool = field(default=False, repr=False)
    _halt_reason: str = field(default="", repr=False)

    def observe(self, record: dict[str, Any]) -> MonitorVerdict:
        """Feed one post-dispatch record; return the current verdict.

        Record shape: {"tool": str, "success": bool, "args_digest": str, ...}
        Extra fields are ignored.
        """
        if self._halted:
            return "HALT"
        self._window.append(record)
        while len(self._window) > self.window_size:
            self._window.popleft()
        return self._check_invariants()

    def _check_invariants(self) -> MonitorVerdict:
        if not self._window:
            return "OK"

        # 1. Error rate.
        errors = sum(1 for r in self._window if not r.get("success", True))
        error_rate = errors / len(self._window)
        if error_rate > self.max_error_rate:
            return self._halt(f"error rate {error_rate:.1%} exceeds {self.max_error_rate:.0%}")

        # 2. Oscillation: same (tool, args) retried with mixed outcomes.
        seen: dict[tuple[str, str], list[bool]] = {}
        for r in self._window:
            key = (str(r.get("tool", "")), str(r.get("args_digest", "")))
            seen.setdefault(key, []).append(bool(r.get("success", True)))
        for key, outcomes in seen.items():
            if len(outcomes) > self.max_retries and len(set(outcomes)) > 1:
                return self._halt(f"oscillation: {key[0]} retried {len(outcomes)}x with mixed outcomes")

        # 3. Quota: too many calls in the window.
        if len(self._window) >= self.max_calls_per_window:
            return self._halt(f"quota: {len(self._window)} calls in window (max {self.max_calls_per_window})")

        # WARN if approaching the error threshold.
        if error_rate > self.warn_error_rate:
            return "WARN"
        return "OK"

    def _halt(self, reason: str) -> MonitorVerdict:
        self._halted = True
        self._halt_reason = reason
        return "HALT"

    @property
    def halt_reason(self) -> str:
        return self._halt_reason

    def reset(self) -> None:
        """Clear the window and the halted state (e.g. after human review)."""
        self._window.clear()
        self._halted = False
        self._halt_reason = ""
