"""SLO tracker: service-level objectives, error budgets, and burn-rate alerts.

Research note: the SLO/error-budget discipline comes from Google's SRE
book — a service-level objective (e.g. "99.9% of requests succeed over
any rolling 28-day window") turns reliability into a number, and the
*error budget* (the 0.1% you are allowed to get wrong) is the resource
you spend on risk. Burn rate is how fast you are spending it: a burn
rate of 1 means you will exhaust the budget exactly at the end of the
window; 2 means twice as fast; Google SRE's multi-window alerting fires
on fast burns over short windows and slow burns over long ones.

Design (single-host bookkeeping, house style throughout):

* **Objectives** — ``define_objective(objective_id, target, window_events)``
  declares a target success ratio in (0, 1) and a rolling event window.
  Allowed failures per window = ``(1 - target) * window_events``.
* **Recording** — ``record(objective_id, success, seq)`` appends a boolean
  outcome to the objective's bounded rolling deque. Caller-supplied int
  ``seq`` values are strictly increasing across the tracker (no wall
  clock anywhere).
* **Budget** — ``budget(objective_id)`` returns the remaining fraction of
  the error budget: ``1 - observed_failures / allowed_failures``. Negative
  means the budget is exhausted (the objective is in violation).
* **Burn rate** — ``burn_rate(objective_id)`` returns
  ``observed_error_ratio / allowed_error_ratio``. 0 with no events, 1.0
  when spending exactly at the allowed pace. Fail-closed: unknown
  objectives, malformed ids, non-bool outcomes, and non-monotonic seqs
  raise instead of silently corrupting the ledger.

Honest scope: this module books *host-reported* outcomes — it cannot
observe real traffic, prove an outcome was measured honestly, or detect
a host that lies about success. A "budget exhausted" verdict means "the
reported numbers spent the budget", never "the service is down". Burn
rate is a pacing signal, not a predictor: it cannot guarantee future
error rates. In-memory only; pair with a durable audit writer for crash
recovery.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import RLock
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple

#: Module version pin.
SLO_TRACKER_VERSION = "slo-tracker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.slo-tracker.v1"

#: Audit event schema this module shapes records for.
AUDIT_SCHEMA = "audit.ndjson/1"


class SLOError(Exception):
    """Malformed input to the SLO tracker (programming error)."""


class DuplicateObjectiveError(SLOError):
    """Raised when defining an objective id that already exists."""


class UnknownObjectiveError(SLOError):
    """Raised when an objective id is not defined."""


class SeqOrderError(SLOError):
    """Raised when a caller seq does not strictly increase."""


def _check_str(value: Any, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SLOError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise SLOError(f"{name} must be non-empty")
    return value


def _check_target(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SLOError(f"target must be a number in (0, 1), got {type(value).__name__}")
    v = float(value)
    if not (0.0 < v < 1.0):
        raise SLOError(f"target must be in (0, 1), got {v!r}")
    return v


def _check_window(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SLOError(f"window_events must be a positive int, got {type(value).__name__}")
    if value < 1:
        raise SLOError("window_events must be >= 1")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SLOError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise SLOError("seq must be non-negative")
    return value


def _check_success(value: Any) -> bool:
    if not isinstance(value, bool):
        raise SLOError(f"success must be a bool, got {type(value).__name__}")
    return value


@dataclass(frozen=True)
class ObjectiveRecord:
    """A defined SLO objective."""

    objective_id: str
    target: float
    window_events: int
    allowed_error_ratio: float
    allowed_failures: float
    seq: int
    version: str = SLO_TRACKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "target": self.target,
            "window_events": self.window_events,
            "allowed_error_ratio": self.allowed_error_ratio,
            "allowed_failures": self.allowed_failures,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class BudgetReport:
    """Error-budget state for one objective."""

    objective_id: str
    target: float
    window_events: int
    allowed_failures: float
    observed_failures: int
    events_in_window: int
    consumed: float
    remaining: float
    exhausted: bool
    seq: int
    version: str = SLO_TRACKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "target": self.target,
            "window_events": self.window_events,
            "allowed_failures": self.allowed_failures,
            "observed_failures": self.observed_failures,
            "events_in_window": self.events_in_window,
            "consumed": self.consumed,
            "remaining": self.remaining,
            "exhausted": self.exhausted,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class BurnRateReport:
    """Burn-rate state for one objective."""

    objective_id: str
    target: float
    allowed_error_ratio: float
    observed_error_ratio: float
    burn_rate: float
    events_in_window: int
    seq: int
    version: str = SLO_TRACKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "target": self.target,
            "allowed_error_ratio": self.allowed_error_ratio,
            "observed_error_ratio": self.observed_error_ratio,
            "burn_rate": self.burn_rate,
            "events_in_window": self.events_in_window,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SLOStatus:
    """Combined budget + burn view for one objective."""

    budget: BudgetReport
    burn: BurnRateReport
    version: str = SLO_TRACKER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "budget": self.budget.as_dict(),
            "burn": self.burn.as_dict(),
            "version": self.version,
            "schema": self.schema,
        }


_AUDIT_KINDS: FrozenSet[str] = frozenset(
    {"objective-defined", "event-recorded", "rejected"}
)


def slo_tracker_audit_event(kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for SLO-tracker activity.

    Carries ids, counts, and verdicts only — never raw payload data.
    """
    if kind not in _AUDIT_KINDS:
        raise SLOError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if detail is not None and not isinstance(detail, Mapping):
        raise SLOError("detail must be a mapping")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": f"slo-tracker.{kind}",
        "module": "slo_tracker",
        "module_version": SLO_TRACKER_VERSION,
        "seq": seq,
        "detail": dict(detail) if detail else {},
    }


class SLOTracker:
    """Tracks SLO objectives, error budgets, and burn rates.

    Thread-safe. All state is host-reported bookkeeping; see the module
    docstring for the honest scope.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._objectives: Dict[str, ObjectiveRecord] = {}
        self._events: Dict[str, deque] = {}
        self._last_seq = -1

    def _next_seq(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def define_objective(self, objective_id: str, target: float, window_events: int, seq: int) -> ObjectiveRecord:
        """Define a new SLO objective."""
        oid = _check_str(objective_id, "objective_id")
        t = _check_target(target)
        w = _check_window(window_events)
        s = _check_seq(seq)
        with self._lock:
            if oid in self._objectives:
                raise DuplicateObjectiveError(f"objective {oid!r} already defined")
            self._next_seq(s)
            allowed_ratio = 1.0 - t
            rec = ObjectiveRecord(
                objective_id=oid,
                target=t,
                window_events=w,
                allowed_error_ratio=allowed_ratio,
                allowed_failures=allowed_ratio * w,
                seq=s,
            )
            self._objectives[oid] = rec
            self._events[oid] = deque(maxlen=w)
            return rec

    def record(self, objective_id: str, success: bool, seq: int) -> None:
        """Record one outcome against an objective."""
        oid = _check_str(objective_id, "objective_id")
        ok = _check_success(success)
        s = _check_seq(seq)
        with self._lock:
            if oid not in self._objectives:
                raise UnknownObjectiveError(f"unknown objective {oid!r}")
            self._next_seq(s)
            self._events[oid].append(ok)

    def objectives(self) -> Tuple[str, ...]:
        """Sorted tuple of defined objective ids."""
        with self._lock:
            return tuple(sorted(self._objectives))

    def objective(self, objective_id: str) -> ObjectiveRecord:
        """Return the definition record for one objective."""
        oid = _check_str(objective_id, "objective_id")
        with self._lock:
            if oid not in self._objectives:
                raise UnknownObjectiveError(f"unknown objective {oid!r}")
            return self._objectives[oid]

    def budget(self, objective_id: str, seq: int) -> BudgetReport:
        """Compute the remaining error-budget fraction for one objective."""
        oid = _check_str(objective_id, "objective_id")
        s = _check_seq(seq)
        with self._lock:
            if oid not in self._objectives:
                raise UnknownObjectiveError(f"unknown objective {oid!r}")
            self._next_seq(s)
            obj = self._objectives[oid]
            window = self._events[oid]
            observed_failures = sum(1 for ok in window if not ok)
            consumed = observed_failures / obj.allowed_failures if obj.allowed_failures > 0 else 0.0
            remaining = 1.0 - consumed
            return BudgetReport(
                objective_id=oid,
                target=obj.target,
                window_events=obj.window_events,
                allowed_failures=obj.allowed_failures,
                observed_failures=observed_failures,
                events_in_window=len(window),
                consumed=consumed,
                remaining=remaining,
                exhausted=remaining < 0.0,
                seq=s,
            )

    def burn_rate(self, objective_id: str, seq: int) -> BurnRateReport:
        """Compute the burn rate for one objective over its rolling window.

        Burn rate = observed error ratio / allowed error ratio.
        1.0 spends the budget exactly on schedule; >1 spends it faster;
        0.0 when no events (or no failures) have been recorded.
        """
        oid = _check_str(objective_id, "objective_id")
        s = _check_seq(seq)
        with self._lock:
            if oid not in self._objectives:
                raise UnknownObjectiveError(f"unknown objective {oid!r}")
            self._next_seq(s)
            obj = self._objectives[oid]
            window = self._events[oid]
            n = len(window)
            if n == 0:
                observed_ratio = 0.0
            else:
                observed_ratio = sum(1 for ok in window if not ok) / n
            rate = observed_ratio / obj.allowed_error_ratio if obj.allowed_error_ratio > 0 else 0.0
            return BurnRateReport(
                objective_id=oid,
                target=obj.target,
                allowed_error_ratio=obj.allowed_error_ratio,
                observed_error_ratio=observed_ratio,
                burn_rate=rate,
                events_in_window=n,
                seq=s,
            )

    def status(self, objective_id: str, seq: int) -> SLOStatus:
        """Combined budget + burn-rate report for one objective."""
        oid = _check_str(objective_id, "objective_id")
        s = _check_seq(seq)
        with self._lock:
            if oid not in self._objectives:
                raise UnknownObjectiveError(f"unknown objective {oid!r}")
            self._next_seq(s)
            obj = self._objectives[oid]
            window = self._events[oid]
            n = len(window)
            failures = sum(1 for ok in window if not ok)
            consumed = failures / obj.allowed_failures if obj.allowed_failures > 0 else 0.0
            remaining = 1.0 - consumed
            observed_ratio = failures / n if n else 0.0
            rate = observed_ratio / obj.allowed_error_ratio if obj.allowed_error_ratio > 0 else 0.0
            return SLOStatus(
                budget=BudgetReport(
                    objective_id=oid,
                    target=obj.target,
                    window_events=obj.window_events,
                    allowed_failures=obj.allowed_failures,
                    observed_failures=failures,
                    events_in_window=n,
                    consumed=consumed,
                    remaining=remaining,
                    exhausted=remaining < 0.0,
                    seq=s,
                ),
                burn=BurnRateReport(
                    objective_id=oid,
                    target=obj.target,
                    allowed_error_ratio=obj.allowed_error_ratio,
                    observed_error_ratio=observed_ratio,
                    burn_rate=rate,
                    events_in_window=n,
                    seq=s,
                ),
            )


def main() -> None:
    t = SLOTracker()
    t.define_objective("api-availability", 0.99, 100, seq=1)
    for i in range(95):
        t.record("api-availability", True, seq=2 + i)
    t.record("api-availability", False, seq=97)
    b = t.budget("api-availability", seq=98)
    r = t.burn_rate("api-availability", seq=99)
    assert b.observed_failures == 1
    assert abs(r.burn_rate - 1.0416666666666667) < 1e-9
    assert not b.exhausted
    print(
        "slo-tracker OK: define, record, budget, burn_rate "
        f"(remaining={b.remaining:.3f}, burn={r.burn_rate:.3f})"
    )


if __name__ == "__main__":
    main()
