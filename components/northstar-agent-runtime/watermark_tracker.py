"""Event-time watermark tracking (Flink-style) over caller-supplied time.

A ``WatermarkTracker`` answers the streaming question "up to which event
time do I believe all events have arrived?" without a wall clock:

* ``update(event_time_ms)`` records one observed event (host-reported
  event time, caller-supplied int milliseconds). The tracker keeps the
  maximum observed event time and derives the watermark as
  ``max_seen - max_out_of_orderness_ms``.
* The watermark is *monotonic*: it never moves backwards, even when late
  events arrive. A late event is observed but never regresses progress.
* ``current()`` returns the watermark, or ``None`` when nothing
  meaningful can be said yet (no events seen, or the maximum is still
  within the out-of-orderness bound).
* ``lateness(event_time_ms)`` classifies one event against the current
  watermark: ``on-time`` (at or past the watermark), ``late`` (behind
  the watermark but within the allowed lateness), ``too-late`` (behind
  the watermark *minus* the allowed lateness -- a Flink window would
  drop it).

House style: no wall-clock -- all timestamps are caller-supplied int
milliseconds. Frozen records, fail-closed validation, stdlib-only,
deterministic, version/schema pins, ``main()`` self-check.

Honest scope: the tracker reasons about *host-reported* event times
only. A watermark means "the host says everything up to here has
arrived", never "the data source is actually complete" -- an unreported
event leaves no trace. A late event is not corrupt data, just data that
arrived after its event time was judged complete; ``too-late`` is a
policy verdict about dropping, not a verdict about truth.

Version pin: watermark-tracker.v1
Schema pin: northstar.watermark-tracker.v1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

#: Module version.
WATERMARK_TRACKER_VERSION = "watermark-tracker.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.watermark-tracker.v1"

#: Lateness classifications.
STATUS_ON_TIME = "on-time"
STATUS_LATE = "late"
STATUS_TOO_LATE = "too-late"

#: Audit event kinds.
AUDIT_CREATED = "created"
AUDIT_OBSERVED = "event-observed"
AUDIT_ADVANCED = "watermark-advanced"
AUDIT_LATE = "late-event"
AUDIT_TOO_LATE = "too-late-event"

_AUDIT_KINDS = frozenset(
    {
        AUDIT_CREATED,
        AUDIT_OBSERVED,
        AUDIT_ADVANCED,
        AUDIT_LATE,
        AUDIT_TOO_LATE,
    }
)


class WatermarkError(Exception):
    """Fail-closed error for watermark tracker misuse."""


def _require_ms(name: str, value) -> None:
    """Validate a caller-supplied millisecond timestamp (non-negative)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int (ms), got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_bound(name: str, value) -> None:
    """Validate a lateness/out-of-orderness bound (non-negative int)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int (ms), got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class WatermarkUpdate:
    """Result of one ``update()`` call."""

    version: str
    event_time: int
    previous_watermark: Optional[int]
    watermark: Optional[int]
    advanced: bool

    def __post_init__(self) -> None:
        if self.version != SCHEMA_PIN:
            raise WatermarkError("schema pin mismatch")
        if not isinstance(self.event_time, int):
            raise WatermarkError("event_time must be an int")
        if self.previous_watermark is not None and not isinstance(
            self.previous_watermark, int
        ):
            raise WatermarkError("previous_watermark must be an int or None")
        if self.watermark is not None and not isinstance(self.watermark, int):
            raise WatermarkError("watermark must be an int or None")
        if not isinstance(self.advanced, bool):
            raise WatermarkError("advanced must be a bool")

    def as_dict(self) -> dict:
        return {
            "schema": self.version,
            "event_time": self.event_time,
            "previous_watermark": self.previous_watermark,
            "watermark": self.watermark,
            "advanced": self.advanced,
        }


@dataclass(frozen=True)
class LatenessReport:
    """Classification of one event time against the current watermark."""

    version: str
    event_time: int
    watermark: int
    lateness_ms: int
    status: str

    def __post_init__(self) -> None:
        if self.version != SCHEMA_PIN:
            raise WatermarkError("schema pin mismatch")
        if not isinstance(self.event_time, int):
            raise WatermarkError("event_time must be an int")
        if not isinstance(self.watermark, int):
            raise WatermarkError("watermark must be an int")
        if not isinstance(self.lateness_ms, int) or self.lateness_ms < 0:
            raise WatermarkError("lateness_ms must be a non-negative int")
        if self.status not in (STATUS_ON_TIME, STATUS_LATE, STATUS_TOO_LATE):
            raise WatermarkError(f"unknown status: {self.status!r}")

    def as_dict(self) -> dict:
        return {
            "schema": self.version,
            "event_time": self.event_time,
            "watermark": self.watermark,
            "lateness_ms": self.lateness_ms,
            "status": self.status,
        }


class WatermarkTracker:
    """Flink-style event-time watermark tracker.

    ``max_out_of_orderness_ms`` bounds how long the tracker waits for
    out-of-order events before declaring an event time complete; the
    watermark trails the maximum observed event time by exactly that
    much. ``allowed_lateness_ms`` widens the window for already-late
    events before they are classified ``too-late``.
    """

    def __init__(
        self, max_out_of_orderness_ms: int = 0, allowed_lateness_ms: int = 0
    ) -> None:
        _require_bound("max_out_of_orderness_ms", max_out_of_orderness_ms)
        _require_bound("allowed_lateness_ms", allowed_lateness_ms)
        self._ooo = max_out_of_orderness_ms
        self._allowed = allowed_lateness_ms
        self._max_seen: Optional[int] = None
        self._watermark: Optional[int] = None
        self._event_count = 0
        self._late_count = 0
        self._too_late_count = 0

    # -- core API --------------------------------------------------------

    def update(self, event_time_ms: int) -> WatermarkUpdate:
        """Record one observed event time; advance the watermark if able."""
        _require_ms("event_time_ms", event_time_ms)
        previous = self._watermark
        if self._max_seen is None or event_time_ms > self._max_seen:
            self._max_seen = event_time_ms
        self._event_count += 1
        candidate = self._max_seen - self._ooo
        new_watermark = candidate if candidate >= 0 else None
        advanced = (
            new_watermark is not None
            and (previous is None or new_watermark > previous)
        )
        if advanced:
            self._watermark = new_watermark
        return WatermarkUpdate(
            version=SCHEMA_PIN,
            event_time=event_time_ms,
            previous_watermark=previous,
            watermark=self._watermark,
            advanced=advanced,
        )

    def current(self) -> Optional[int]:
        """The current watermark, or None when none can be claimed yet."""
        return self._watermark

    def lateness(self, event_time_ms: int) -> LatenessReport:
        """Classify one event time against the current watermark."""
        _require_ms("event_time_ms", event_time_ms)
        watermark = self._watermark
        if watermark is None:
            raise WatermarkError(
                "no watermark yet: update() before calling lateness()"
            )
        gap = watermark - event_time_ms
        lateness_ms = gap if gap > 0 else 0
        if event_time_ms >= watermark:
            status = STATUS_ON_TIME
        elif event_time_ms >= watermark - self._allowed:
            status = STATUS_LATE
        else:
            status = STATUS_TOO_LATE
        if status == STATUS_LATE:
            self._late_count += 1
        elif status == STATUS_TOO_LATE:
            self._too_late_count += 1
        return LatenessReport(
            version=SCHEMA_PIN,
            event_time=event_time_ms,
            watermark=watermark,
            lateness_ms=lateness_ms,
            status=status,
        )

    # -- views -----------------------------------------------------------

    def max_event_time(self) -> Optional[int]:
        """Maximum observed event time, or None if no events."""
        return self._max_seen

    def event_count(self) -> int:
        """Total events observed via ``update()``."""
        return self._event_count

    def late_count(self) -> int:
        """Events classified ``late`` by ``lateness()`` so far."""
        return self._late_count

    def too_late_count(self) -> int:
        """Events classified ``too-late`` by ``lateness()`` so far."""
        return self._too_late_count

    def bounds(self) -> tuple[int, int]:
        """(max_out_of_orderness_ms, allowed_lateness_ms)."""
        return (self._ooo, self._allowed)


def watermark_tracker_audit_event(kind: str, seq: int, **fields) -> dict:
    """Audit-shaped record for a watermark tracker transition."""
    if kind not in _AUDIT_KINDS:
        raise WatermarkError(f"unknown audit kind: {kind!r}")
    _require_ms("seq", seq)
    event: dict = {
        "schema": SCHEMA_PIN,
        "audit_seq": seq,
        "kind": kind,
        "module_version": WATERMARK_TRACKER_VERSION,
    }
    event.update(fields)
    return event


def main() -> None:
    tracker = WatermarkTracker(max_out_of_orderness_ms=100, allowed_lateness_ms=50)
    assert tracker.current() is None, "no watermark before any events"
    r1 = tracker.update(500)
    assert r1.watermark == 400, f"500 - 100 = 400, got {r1.watermark}"
    assert r1.advanced, "first meaningful watermark must advance"
    # Late arrival: observed, but the watermark must not regress.
    r2 = tracker.update(250)
    assert not r2.advanced, "late event must not advance the watermark"
    assert tracker.current() == 400, "watermark must never move backwards"
    # Lateness classification against watermark 400.
    rep = tracker.lateness(420)
    assert rep.status == STATUS_ON_TIME, f"420 >= 400, got {rep.status}"
    rep = tracker.lateness(370)
    assert rep.status == STATUS_LATE and rep.lateness_ms == 30, f"{rep}"
    rep = tracker.lateness(300)
    assert rep.status == STATUS_TOO_LATE, f"300 < 400 - 50, got {rep.status}"
    assert tracker.late_count() == 1 and tracker.too_late_count() == 1
    print("watermark-tracker OK: monotonic, late bounded, too-late dropped")


if __name__ == "__main__":
    main()
