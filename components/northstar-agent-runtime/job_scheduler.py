"""Job scheduler: cron and one-shot scheduling as a deterministic state machine.

Research motivation: schedulers decide *when* untrusted code runs. In an
agent runtime the schedule is part of the policy surface -- a job that
fires too often bypasses rate limits, a job that fires too late misses
an SLA, and a job whose identity the module cannot pin is a confused
deputy. This module is the *bookkeeping* half of a scheduler: it decides
which registered jobs are due at a caller-supplied logical tick, but it
never sleeps, never spawns threads, and never executes a payload itself --
the host applies the due-set through its own ``applier``. That keeps
time out of the module: the caller passes integer logical ticks
(seconds since some epoch), so schedule decisions are replayable and
audit-deterministic.

Public API:

- ``JobScheduler`` -- RLock-guarded registry.
  ``schedule(job_id, spec, seq)`` registers a ``CronSpec`` or a
  ``OneShotSpec``. ``cancel(job_id, seq)`` removes a job.
  ``trigger(job_id, seq)`` fires a job immediately (manual override),
  one-shot jobs are consumed by a trigger. ``due(tick, seq)`` returns
  the frozen set of jobs due at logical tick ``tick`` and advances
  their last-fire markers. ``next_fire(job_id, tick)`` computes the
  next due tick strictly after ``tick`` (no firing side effects).
- ``CronSpec`` -- frozen: 5-field cron ``"min hour dom mon dow"``
  (``*``, ranges, steps, lists). One-shot: ``OneShotSpec`` fires at a
  single tick.
- ``parse_cron(expr)`` -- parses a 5-field expression fail-closed.
- ``job_scheduler_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records, fixed kind vocabulary: ``"scheduled"``, ``"cancelled"``,
  ``"triggered"``, ``"fired"``, ``"rejected"``.

Honest scope:

- The module answers "which jobs are due at tick T" -- it does not
  *execute* anything, does not measure real time, and does not detect a
  host that reports the wrong tick. A host that lies about the tick gets
  a perfectly consistent schedule of lies (same GIGO boundary as every
  other bookkeeping module in this tree).
- Cron fields are computed over caller-supplied ticks converted with
  ``gmtime`` (UTC), so the schedule is independent of the host's
  timezone database. Tick must be a non-negative int.
- One-shot jobs fire once (via ``due`` or ``trigger``) and are removed;
  cron jobs live until cancelled. ``due`` fires a cron job at most once
  per tick per job.

Version pin: ``job-scheduler.v1`` / schema pin
``northstar.job-scheduler.v1``.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

VERSION = "job-scheduler.v1"
SCHEMA = "northstar.job-scheduler.v1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SchedulerError(Exception):
    """Base class for scheduler errors."""


class CronParseError(SchedulerError):
    """A cron expression could not be parsed."""


class DuplicateJobError(SchedulerError):
    """A job id is already registered."""


class UnknownJobError(SchedulerError):
    """No registered job with that id."""


# ---------------------------------------------------------------------------
# Cron parsing
# ---------------------------------------------------------------------------

_FIELD_BOUNDS = (0, 59, 0, 23, 1, 31, 1, 12, 0, 6)  # (lo, hi) x5
_FIELD_NAMES = ("minute", "hour", "day-of-month", "month", "day-of-week")

_MONTH_ALIASES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_DOW_ALIASES = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SchedulerError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _token_to_num(token: str, field_index: int) -> int:
    token = token.strip()
    if token == "":
        raise CronParseError("empty token")
    lowered = token.lower()
    if field_index == 3 and lowered in _MONTH_ALIASES:
        return _MONTH_ALIASES[lowered]
    if field_index == 4 and lowered in _DOW_ALIASES:
        return _DOW_ALIASES[lowered]
    if lowered.startswith("-") or not lowered.lstrip("+").isdigit():
        raise CronParseError(f"bad token {token!r} in {_FIELD_NAMES[field_index]}")
    value = int(lowered)
    lo, hi = _FIELD_BOUNDS[2 * field_index], _FIELD_BOUNDS[2 * field_index + 1]
    # Accept 7 for Sunday in day-of-week.
    if field_index == 4 and value == 7:
        value = 0
    if not (lo <= value <= hi):
        raise CronParseError(
            f"value {value} out of range [{lo}, {hi}] in {_FIELD_NAMES[field_index]}"
        )
    return value


def _parse_field(text: str, field_index: int) -> FrozenSet[int]:
    lo, hi = _FIELD_BOUNDS[2 * field_index], _FIELD_BOUNDS[2 * field_index + 1]
    out: Set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if part == "":
            raise CronParseError(f"empty list element in {_FIELD_NAMES[field_index]}")
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) <= 0:
                raise CronParseError(
                    f"bad step {step_text!r} in {_FIELD_NAMES[field_index]}"
                )
            step = int(step_text)
        if part in ("", "*"):
            start, end = lo, hi
        elif "-" in part:
            start_text, end_text = part.split("-", 1)
            start = _token_to_num(start_text, field_index)
            end = _token_to_num(end_text, field_index)
            if end < start:
                raise CronParseError(
                    f"reversed range {part!r} in {_FIELD_NAMES[field_index]}"
                )
        else:
            start = end = _token_to_num(part, field_index)
        for value in range(start, end + 1, step):
            out.add(value)
    if not out:
        raise CronParseError(f"empty field in {_FIELD_NAMES[field_index]}")
    return frozenset(out)


def parse_cron(expr: object) -> "CronSpec":
    """Parse a 5-field cron expression fail-closed."""
    if not isinstance(expr, str):
        raise CronParseError(f"cron expression must be str, got {type(expr).__name__}")
    fields = expr.split()
    if len(fields) != 5:
        raise CronParseError(
            f"cron expression must have exactly 5 fields, got {len(fields)}"
        )
    return CronSpec(
        minute=_parse_field(fields[0], 0),
        hour=_parse_field(fields[1], 1),
        day_of_month=_parse_field(fields[2], 2),
        month=_parse_field(fields[3], 3),
        day_of_week=_parse_field(fields[4], 4),
    )


# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CronSpec:
    minute: FrozenSet[int]
    hour: FrozenSet[int]
    day_of_month: FrozenSet[int]
    month: FrozenSet[int]
    day_of_week: FrozenSet[int]

    def matches(self, tick: int) -> bool:
        """True if the cron spec fires at logical tick ``tick`` (UTC)."""
        tm = time.gmtime(tick)
        return (
            tm.tm_min in self.minute
            and tm.tm_hour in self.hour
            and tm.tm_mday in self.day_of_month
            and tm.tm_mon in self.month
            # time.gmtime: Monday=0 .. Sunday=6; cron: Sunday=0.
            and (tm.tm_wday + 1) % 7 in self.day_of_week
        )

    def next_after(self, tick: int, limit_ticks: int = 525_600) -> Optional[int]:
        """Next tick strictly after ``tick`` that matches, or None.

        Scans minute by minute up to ``limit_ticks`` (one leap year by
        default); fail-closed on non-progress.
        """
        if isinstance(tick, bool) or not isinstance(tick, int) or tick < 0:
            raise SchedulerError(f"tick must be a non-negative int, got {tick!r}")
        # Align to the next minute boundary.
        candidate = tick + 60 - (tick % 60)
        for _ in range(limit_ticks):
            if self.matches(candidate):
                return candidate
            candidate += 60
        return None


@dataclass(frozen=True)
class OneShotSpec:
    at_tick: int

    def __post_init__(self) -> None:
        if isinstance(self.at_tick, bool) or not isinstance(self.at_tick, int) \
                or self.at_tick < 0:
            raise SchedulerError(
                f"at_tick must be a non-negative int, got {self.at_tick!r}"
            )


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class JobRecord:
    job_id: str
    spec: object  # CronSpec | OneShotSpec
    seq: int
    digest: str

    @staticmethod
    def make(job_id: str, spec: object, seq: int) -> "JobRecord":
        if not isinstance(job_id, str) or not job_id:
            raise SchedulerError(f"job_id must be a non-empty str, got {job_id!r}")
        kind = "cron" if isinstance(spec, CronSpec) else "oneshot"
        body = f"{VERSION}\n{kind}\n{job_id}\n{seq}".encode("utf-8")
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        return JobRecord(job_id=job_id, spec=spec, seq=seq, digest=digest)


@dataclass(frozen=True)
class DueReport:
    tick: int
    due_job_ids: Tuple[str, ...]
    seq: int

    def as_dict(self) -> Dict[str, object]:
        return {"tick": self.tick, "due": list(self.due_job_ids), "seq": self.seq}


@dataclass(frozen=True)
class FireEvent:
    job_id: str
    tick: int
    seq: int
    manual: bool
    digest: str


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class JobScheduler:
    """Deterministic cron / one-shot schedule bookkeeping (RLock-guarded)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: Dict[str, JobRecord] = {}
        self._cron_last_fired: Dict[str, int] = {}
        self._events: List[FireEvent] = []
        self._seq = 0

    # -- mutation ------------------------------------------------------

    def schedule(self, job_id: str, spec: object, seq: int) -> JobRecord:
        seq = _check_seq(seq)
        if not isinstance(spec, (CronSpec, OneShotSpec)):
            raise SchedulerError(
                f"spec must be CronSpec or OneShotSpec, got {type(spec).__name__}"
            )
        with self._lock:
            if job_id in self._jobs:
                raise DuplicateJobError(f"job {job_id!r} already scheduled")
            record = JobRecord.make(job_id, spec, seq)
            self._jobs[job_id] = record
            self._seq = max(self._seq, seq)
            return record

    def cancel(self, job_id: str, seq: int) -> JobRecord:
        seq = _check_seq(seq)
        with self._lock:
            try:
                record = self._jobs.pop(job_id)
            except KeyError:
                raise UnknownJobError(f"unknown job {job_id!r}") from None
            self._cron_last_fired.pop(job_id, None)
            self._seq = max(self._seq, seq)
            return record

    def trigger(self, job_id: str, seq: int) -> FireEvent:
        """Fire a job manually; consumes one-shot jobs."""
        seq = _check_seq(seq)
        with self._lock:
            try:
                record = self._jobs[job_id]
            except KeyError:
                raise UnknownJobError(f"unknown job {job_id!r}") from None
            digest = "sha256:" + hashlib.sha256(
                f"{VERSION}\nmanual\n{job_id}\n{seq}".encode("utf-8")
            ).hexdigest()
            event = FireEvent(
                job_id=job_id, tick=-1, seq=seq, manual=True, digest=digest
            )
            self._events.append(event)
            if isinstance(record.spec, OneShotSpec):
                del self._jobs[job_id]
                self._cron_last_fired.pop(job_id, None)
            self._seq = max(self._seq, seq)
            return event

    # -- queries -------------------------------------------------------

    def jobs(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._jobs))

    def record(self, job_id: str) -> JobRecord:
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError:
                raise UnknownJobError(f"unknown job {job_id!r}") from None

    def due(self, tick: int, seq: int) -> DueReport:
        """Jobs due at logical tick ``tick``; advances fire markers."""
        if isinstance(tick, bool) or not isinstance(tick, int) or tick < 0:
            raise SchedulerError(f"tick must be a non-negative int, got {tick!r}")
        seq = _check_seq(seq)
        fired: List[str] = []
        with self._lock:
            for job_id, record in sorted(self._jobs.items()):
                spec = record.spec
                if isinstance(spec, CronSpec):
                    if spec.matches(tick) and self._cron_last_fired.get(job_id) != tick:
                        fired.append(job_id)
                        self._cron_last_fired[job_id] = tick
                else:  # OneShotSpec
                    if spec.at_tick == tick:
                        fired.append(job_id)
            for job_id in fired:
                record = self._jobs[job_id]
                digest = "sha256:" + hashlib.sha256(
                    f"{VERSION}\ntick\n{job_id}\n{tick}\n{seq}".encode("utf-8")
                ).hexdigest()
                self._events.append(
                    FireEvent(
                        job_id=job_id, tick=tick, seq=seq, manual=False, digest=digest
                    )
                )
                if isinstance(record.spec, OneShotSpec):
                    del self._jobs[job_id]
                    self._cron_last_fired.pop(job_id, None)
            self._seq = max(self._seq, seq)
            return DueReport(tick=tick, due_job_ids=tuple(fired), seq=seq)

    def next_fire(self, job_id: str, tick: int) -> Optional[int]:
        """Next due tick strictly after ``tick``; no side effects."""
        with self._lock:
            try:
                record = self._jobs[job_id]
            except KeyError:
                raise UnknownJobError(f"unknown job {job_id!r}") from None
        spec = record.spec
        if isinstance(spec, CronSpec):
            return spec.next_after(tick)
        return spec.at_tick if spec.at_tick > tick else None

    def events(self) -> Tuple[FireEvent, ...]:
        with self._lock:
            return tuple(self._events)

    # -- audit ---------------------------------------------------------

    def audit_event(self, kind: str, seq: int, job_id: str = "") -> Dict[str, object]:
        seq = _check_seq(seq)
        if kind not in ("scheduled", "cancelled", "triggered", "fired", "rejected"):
            raise SchedulerError(f"unknown audit kind {kind!r}")
        return {
            "kind": f"job-scheduler.{kind}",
            "schema": SCHEMA,
            "version": VERSION,
            "seq": seq,
            "job_id": job_id,
        }


def job_scheduler_audit_event(
    kind: str, seq: int, job_id: str = ""
) -> Dict[str, object]:
    """Module-level ``audit.ndjson/1``-shaped record constructor."""
    tmp = JobScheduler()
    return tmp.audit_event(kind, seq, job_id)


def main() -> None:
    sched = JobScheduler()
    sched.schedule("hourly", parse_cron("0 * * * *"), 0)
    sched.schedule("once", OneShotSpec(1_609_459_200 + 3600), 1)
    # 2021-01-01 00:00:00 UTC
    report = sched.due(1_609_459_200, 2)
    assert report.due_job_ids == ("hourly",), report.due_job_ids
    assert sched.next_fire("hourly", 1_609_459_200) == 1_609_462_800
    sched.due(1_609_459_200 + 3600, 3)  # one-shot consumed
    assert "once" not in sched.jobs()
    event = sched.trigger("hourly", 4)
    assert event.manual and event.tick == -1
    print("job-scheduler OK: schedule, due, next_fire, cancel, trigger")


if __name__ == "__main__":
    main()
