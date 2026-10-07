"""Cron scheduler — cron schedule ownership as a deterministic state machine.

Research note (cron): Vixie/ISC cron and its successors (systemd
timers, Kubernetes CronJobs, AWS EventBridge Scheduler) all answer one
question — "which schedules are due now?" — and then layer policy on
top: what happens when a run overlaps the previous one, what happens
when ticks are skipped (a misfire), whether a schedule has a fire
budget, and whether a schedule can be paused without being deleted.
This module is that policy layer as a deterministic single-host
ledger, deliberately distinct from the existing ``job_scheduler`` (the
* firing* layer that owns cron+one-shot tick matching):

* ``job_scheduler`` answers "due at tick T?" and fires.
* ``cron_scheduler`` owns the schedule lifecycle: ``schedule()`` books
  a 5-field cron expression, ``trigger()`` books a manual fire,
  ``cancel()`` is terminal, ``pause()``/``resume()`` freeze and thaw
  without losing the schedule, ``due()`` sweeps a tick and books
  misfires when the host skipped fire points, and fire verdicts
  (fired/skipped/exhausted/paused) are returned **as data**, never
  raised.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* schedules and
*host-reported* runs (``begin_run``/``end_run``). It cannot start a
process, cannot measure real time, and cannot prove a run actually
executed — a ``FireRecord`` is a booked decision, not an execution
receipt. Ticks are caller-supplied logical seconds since epoch,
interpreted in UTC, so the schedule is replayable and
audit-deterministic. GIGO on cron ids, expressions, and tick values:
the ledger pins what the host declares.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: Version pin for this module's record shape.
CRON_SCHEDULER_VERSION = "cron-scheduler.v1"

#: Schema pin carried by records and audit events.
CRON_SCHEDULER_SCHEMA = "northstar.cron-scheduler.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Maximum cron-id length (bookkeeping bound, not a protocol limit).
MAX_CRON_ID_LEN = 256

#: Overlap policy vocabulary.
OVERLAP_SKIP = "skip"
OVERLAP_ALLOW = "allow"
_OVERLAPS = (OVERLAP_SKIP, OVERLAP_ALLOW)

#: Cancel reason vocabulary.
_REASONS = ("manual", "replaced", "expired", "superseded")

#: Audit event kinds.
KIND_SCHEDULED = "cron.scheduled"
KIND_TRIGGERED = "cron.triggered"
KIND_CANCELLED = "cron.cancelled"
KIND_PAUSED = "cron.paused"
KIND_RESUMED = "cron.resumed"
KIND_FIRED = "cron.fired"
KIND_MISFIRED = "cron.misfired"
KIND_RUN_STARTED = "cron.run-started"
KIND_RUN_ENDED = "cron.run-ended"
KIND_REJECTED = "cron.rejected"
_KINDS = (
    KIND_SCHEDULED,
    KIND_TRIGGERED,
    KIND_CANCELLED,
    KIND_PAUSED,
    KIND_RESUMED,
    KIND_FIRED,
    KIND_MISFIRED,
    KIND_RUN_STARTED,
    KIND_RUN_ENDED,
    KIND_REJECTED,
)

#: Fire verdict vocabulary (verdicts are data, never raised).
VERDICT_FIRED = "fired"
VERDICT_SKIPPED = "skipped"
VERDICT_EXHAUSTED = "exhausted"
VERDICT_PAUSED = "paused"

#: Fire source vocabulary.
SOURCE_TRIGGER = "trigger"
SOURCE_DUE = "due"

#: Field bounds for the 5-field expression: min hour dom mon dow.
#: dow accepts 7 as an alias for Sunday (normalized to 0 on parse).
_FIELD_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))

#: Maximum lookback window (ticks) when counting misfires in ``due()``.
#: Bounds the sweep so an epoch-scale tick never causes an O(tick)
#: scan; misfires older than the window are not counted (the host
#: should sweep more often than once per day).
MISFIRE_LOOKBACK_TICKS = 86_400

_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CronSchedulerError(ValueError):
    """Base error for the cron scheduler ledger."""


class BadCronIdError(CronSchedulerError):
    """Malformed cron id."""


class DuplicateCronError(CronSchedulerError):
    """This cron id is already booked."""


class UnknownCronError(CronSchedulerError):
    """No cron job with this id is booked."""


class CancelledCronError(CronSchedulerError):
    """This cron job was cancelled (terminal)."""


class BadCronExprError(CronSchedulerError):
    """Malformed 5-field cron expression."""


class BadFireBudgetError(CronSchedulerError):
    """Malformed max_fires budget."""


class BadOverlapError(CronSchedulerError):
    """Malformed overlap policy."""


class BadReasonError(CronSchedulerError):
    """Malformed cancel reason."""


class BadTickError(CronSchedulerError):
    """Malformed logical tick."""


class RunStateError(CronSchedulerError):
    """begin_run/end_run state violation (double start / end without start)."""


class SeqOrderError(CronSchedulerError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_cron_id(value: Any, name: str = "cron_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadCronIdError(f"{name} must be a non-empty string")
    cron_id = value.strip()
    if len(cron_id) > MAX_CRON_ID_LEN:
        raise BadCronIdError(f"{name} exceeds {MAX_CRON_ID_LEN} chars")
    if any(ch.isspace() for ch in cron_id):
        raise BadCronIdError(f"{name} must not contain whitespace")
    return cron_id


def _check_tick(value: Any, name: str = "tick") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTickError(f"{name} must be an int")
    if value < 0 or value >= 2**31:
        raise BadTickError(f"{name} out of range [0, 2**31)")
    return value


def _canonical(value: Any) -> bytes:
    """Canonical encoding for digest pins (stdlib-only)."""
    try:
        from northstar_agent_runtime import canonical_json  # type: ignore

        payload = canonical_json.dumps(value)
        return payload.encode("utf-8")
    except Exception:
        import json

        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return payload.encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([CRON_SCHEDULER_VERSION, *parts])
    ).hexdigest()
    return f"{_DIGEST_PREFIX}{digest}"


# ---------------------------------------------------------------------------
# Cron expression parsing
# ---------------------------------------------------------------------------


def _parse_field(text: str, lo: int, hi: int) -> frozenset:
    """Parse one cron field: ``*``, ``*/n``, ``a-b``, ``a-b/n``, ``a,b,c``."""
    values: set = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            raise BadCronExprError("empty field token")
        step = 1
        if "/" in token:
            base, step_text = token.split("/", 1)
            if not step_text.isdigit() or int(step_text) <= 0:
                raise BadCronExprError(f"bad step {token!r}")
            step = int(step_text)
        else:
            base = token
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            if not (a.lstrip("-").isdigit() and b.lstrip("-").isdigit()):
                raise BadCronExprError(f"bad range {token!r}")
            start, end = int(a), int(b)
            if start > end:
                raise BadCronExprError(f"reversed range {token!r}")
        else:
            if not base.lstrip("-").isdigit():
                raise BadCronExprError(f"bad value {token!r}")
            start = end = int(base)
        if start < lo or end > hi:
            raise BadCronExprError(f"value {token!r} out of range [{lo},{hi}]")
        for v in range(start, end + 1, step):
            values.add(v)
    if not values:
        raise BadCronExprError("field matched nothing")
    return frozenset(values)


class CronExpr:
    """A parsed 5-field cron expression (``min hour dom mon dow``).

    Immutable after parsing. ``matches(tick)`` evaluates a logical tick
    (seconds since epoch, UTC) with standard cron day semantics: when
    both day-of-month and day-of-week are restricted, either may match
    (OR); otherwise the restricted field decides.
    """

    __slots__ = ("expression", "minute", "hour", "dom", "month", "dow")

    def __init__(self, expression: str) -> None:
        if not isinstance(expression, str):
            raise BadCronExprError("expression must be a string")
        fields = expression.split()
        if len(fields) != 5:
            raise BadCronExprError(
                f"expected 5 fields, got {len(fields)}"
            )
        parsed = [
            _parse_field(text, lo, hi)
            for text, (lo, hi) in zip(fields, _FIELD_BOUNDS)
        ]
        # Sunday may be written as 7; normalize to 0.
        dow = {0 if v == 7 else v for v in parsed[4]}
        object.__setattr__(self, "expression", expression)
        object.__setattr__(self, "minute", parsed[0])
        object.__setattr__(self, "hour", parsed[1])
        object.__setattr__(self, "dom", parsed[2])
        object.__setattr__(self, "month", parsed[3])
        object.__setattr__(self, "dow", frozenset(dow))

    def __setattr__(self, name: str, value: Any) -> None:  # noqa: D105
        raise AttributeError("CronExpr is immutable")

    def matches(self, tick: int) -> bool:
        """True when this expression fires at logical tick ``tick``."""
        _check_tick(tick, "tick")
        tm = time.gmtime(tick)
        cron_dow = (tm.tm_wday + 1) % 7  # gmtime Mon=0 -> cron Sun=0
        if tm.tm_min not in self.minute:
            return False
        if tm.tm_hour not in self.hour:
            return False
        if tm.tm_mon not in self.month:
            return False
        dom_restricted = len(self.dom) < 31
        dow_restricted = len(self.dow) < 7
        dom_hit = tm.tm_mday in self.dom
        dow_hit = cron_dow in self.dow
        if dom_restricted and dow_restricted:
            return dom_hit or dow_hit
        if dom_restricted:
            return dom_hit
        if dow_restricted:
            return dow_hit
        return True

    def digest(self) -> str:
        """Digest pin over the parsed field sets (not the raw string)."""
        return _pin(
            "cron-expr",
            sorted(self.minute),
            sorted(self.hour),
            sorted(self.dom),
            sorted(self.month),
            sorted(self.dow),
        )

    def __repr__(self) -> str:  # noqa: D105
        return f"CronExpr({self.expression!r})"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduleRecord:
    """One booked cron schedule (frozen)."""

    cron_id: str
    expression: str
    expr_digest: str
    max_fires: int
    overlap: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "scheduled",
            self.cron_id,
            self.expression,
            self.max_fires,
            self.overlap,
            self.seq,
        )


@dataclass(frozen=True)
class FireRecord:
    """One booked fire decision (frozen). Verdict is data, never raised."""

    cron_id: str
    source: str
    verdict: str
    misfired: int
    fire_no: int
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "fired",
            self.cron_id,
            self.source,
            self.verdict,
            self.misfired,
            self.fire_no,
            self.seq,
        )


@dataclass(frozen=True)
class CancelRecord:
    """One terminal cancellation (frozen)."""

    cron_id: str
    reason: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "cancelled", self.cron_id, self.reason, self.seq
        )


@dataclass(frozen=True)
class PauseRecord:
    """One pause booking (frozen)."""

    cron_id: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("paused", self.cron_id, self.seq)


@dataclass(frozen=True)
class ResumeRecord:
    """One resume booking (frozen)."""

    cron_id: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("resumed", self.cron_id, self.seq)


@dataclass(frozen=True)
class RunStartRecord:
    """One host-declared run start (frozen). GIGO: the host reports it."""

    cron_id: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("run-started", self.cron_id, self.seq)


@dataclass(frozen=True)
class RunEndRecord:
    """One host-declared run end (frozen). GIGO: the host reports it."""

    cron_id: str
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin("run-ended", self.cron_id, self.seq)


@dataclass(frozen=True)
class DueEntry:
    """One per-job entry inside a due sweep (frozen)."""

    cron_id: str
    fired: bool
    misfired: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "due-entry", self.cron_id, self.fired, self.misfired
        )


@dataclass(frozen=True)
class DueReport:
    """Result of a ``due()`` sweep (frozen)."""

    tick: int
    entries: Tuple[DueEntry, ...]
    seq: int
    digest: str
    schema: str = CRON_SCHEDULER_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "due",
            self.tick,
            [e.digest for e in self.entries],
            self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def cron_scheduler_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the cron scheduler."""
    if kind not in _KINDS:
        raise CronSchedulerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise CronSchedulerError("detail must be a mapping")
    # Only ids, pins, verdicts, and small ints cross the audit boundary.
    banned = {"payload", "value", "raw", "body", "data"}
    if any(k in detail for k in banned):
        raise CronSchedulerError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CRON_SCHEDULER_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class _JobState:
    """Mutable per-job bookkeeping (never leaves the ledger)."""

    __slots__ = (
        "record",
        "expr",
        "status",
        "fires",
        "in_flight",
        "last_swept_tick",
        "disabled",
    )

    def __init__(self, record: ScheduleRecord, expr: CronExpr) -> None:
        self.record = record
        self.expr = expr
        self.status = "active"  # active | paused | cancelled
        self.fires = 0
        self.in_flight = False
        self.last_swept_tick = -1
        self.disabled = False  # fire budget exhausted


class CronScheduler:
    """Deterministic cron schedule-ownership ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: Dict[str, _JobState] = {}
        self._fires: List[FireRecord] = []
        self._audit: List[Dict[str, Any]] = []
        self._last_seq = -1

    # -- internals ------------------------------------------------------

    def _bump(self, seq: int) -> int:
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not strictly increase (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, error: Exception) -> None:
        self._audit.append(
            cron_scheduler_audit_event(
                KIND_REJECTED, {"reason": reason}, seq
            )
        )
        raise error

    def _live(self, cron_id: str, seq: int) -> _JobState:
        cron_id = _check_cron_id(cron_id)
        state = self._jobs.get(cron_id)
        if state is None:
            self._reject(seq, "unknown-cron", UnknownCronError(cron_id))
        assert state is not None  # _reject always raises
        if state.status == "cancelled":
            self._reject(
                seq, "cancelled-cron", CancelledCronError(cron_id)
            )
        return state

    def _book_fire(
        self,
        cron_id: str,
        source: str,
        verdict: str,
        misfired: int,
        seq: int,
        fire_no: int,
    ) -> FireRecord:
        record = FireRecord(
            cron_id=cron_id,
            source=source,
            verdict=verdict,
            misfired=misfired,
            fire_no=fire_no,
            seq=seq,
            digest="",
        )
        record = FireRecord(
            cron_id=record.cron_id,
            source=record.source,
            verdict=record.verdict,
            misfired=record.misfired,
            fire_no=record.fire_no,
            seq=record.seq,
            digest=_pin(
                "fired",
                record.cron_id,
                record.source,
                record.verdict,
                record.misfired,
                record.fire_no,
                record.seq,
            ),
        )
        self._fires.append(record)
        self._audit.append(
            cron_scheduler_audit_event(
                KIND_FIRED if verdict == VERDICT_FIRED else KIND_TRIGGERED,
                {
                    "cron_id": cron_id,
                    "source": source,
                    "verdict": verdict,
                    "misfired": misfired,
                    "fire_no": fire_no,
                },
                seq,
            )
        )
        return record

    # -- public API -----------------------------------------------------

    def schedule(
        self,
        cron_id: str,
        cron_expr: str,
        seq: int,
        max_fires: int = 0,
        overlap: str = OVERLAP_SKIP,
    ) -> ScheduleRecord:
        """Book a cron schedule. ``max_fires=0`` means unlimited."""
        with self._lock:
            self._bump(seq)
            cron_id = _check_cron_id(cron_id)
            if cron_id in self._jobs:
                self._reject(
                    seq, "duplicate-cron", DuplicateCronError(cron_id)
                )
            try:
                expr = CronExpr(cron_expr)
            except BadCronExprError as exc:
                self._reject(seq, "bad-expression", exc)
            if isinstance(max_fires, bool) or not isinstance(max_fires, int):
                self._reject(
                    seq, "bad-fire-budget", BadFireBudgetError("max_fires")
                )
            if max_fires < 0:
                self._reject(
                    seq, "bad-fire-budget", BadFireBudgetError("max_fires")
                )
            if overlap not in _OVERLAPS:
                self._reject(seq, "bad-overlap", BadOverlapError(overlap))
            record = ScheduleRecord(
                cron_id=cron_id,
                expression=cron_expr,
                expr_digest=expr.digest(),
                max_fires=max_fires,
                overlap=overlap,
                seq=seq,
                digest=_pin(
                    "scheduled",
                    cron_id,
                    cron_expr,
                    max_fires,
                    overlap,
                    seq,
                ),
            )
            self._jobs[cron_id] = _JobState(record, expr)
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_SCHEDULED,
                    {
                        "cron_id": cron_id,
                        "expr_digest": record.expr_digest,
                        "max_fires": max_fires,
                        "overlap": overlap,
                    },
                    seq,
                )
            )
            return record

    def trigger(self, cron_id: str, seq: int) -> FireRecord:
        """Book a manual fire. Verdict is data: fired/skipped/exhausted/paused."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if state.status == "paused":
                return self._book_fire(
                    cron_id, SOURCE_TRIGGER, VERDICT_PAUSED, 0, seq,
                    state.fires + 1,
                )
            if state.disabled:
                return self._book_fire(
                    cron_id, SOURCE_TRIGGER, VERDICT_EXHAUSTED, 0, seq,
                    state.fires + 1,
                )
            if state.in_flight and state.record.overlap == OVERLAP_SKIP:
                return self._book_fire(
                    cron_id, SOURCE_TRIGGER, VERDICT_SKIPPED, 0, seq,
                    state.fires + 1,
                )
            state.fires += 1
            if state.record.max_fires and state.fires >= state.record.max_fires:
                state.disabled = True
            return self._book_fire(
                cron_id, SOURCE_TRIGGER, VERDICT_FIRED, 0, seq, state.fires
            )

    def begin_run(self, cron_id: str, seq: int) -> RunStartRecord:
        """Book a host-declared run start (for overlap policy)."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if state.status == "paused":
                self._reject(seq, "paused-cron", RunStateError("paused"))
            if state.in_flight:
                self._reject(
                    seq, "run-already-in-flight", RunStateError("in-flight")
                )
            state.in_flight = True
            record = RunStartRecord(
                cron_id=cron_id,
                seq=seq,
                digest=_pin("run-started", cron_id, seq),
            )
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_RUN_STARTED, {"cron_id": cron_id}, seq
                )
            )
            return record

    def end_run(self, cron_id: str, seq: int) -> RunEndRecord:
        """Book a host-declared run end."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if not state.in_flight:
                self._reject(
                    seq, "no-run-in-flight", RunStateError("not-in-flight")
                )
            state.in_flight = False
            record = RunEndRecord(
                cron_id=cron_id,
                seq=seq,
                digest=_pin("run-ended", cron_id, seq),
            )
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_RUN_ENDED, {"cron_id": cron_id}, seq
                )
            )
            return record

    def pause(self, cron_id: str, seq: int) -> PauseRecord:
        """Pause a schedule without deleting it."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if state.status == "paused":
                self._reject(seq, "already-paused", RunStateError("paused"))
            state.status = "paused"
            record = PauseRecord(
                cron_id=cron_id,
                seq=seq,
                digest=_pin("paused", cron_id, seq),
            )
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_PAUSED, {"cron_id": cron_id}, seq
                )
            )
            return record

    def resume(self, cron_id: str, seq: int) -> ResumeRecord:
        """Resume a paused schedule."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if state.status != "paused":
                self._reject(seq, "not-paused", RunStateError("not-paused"))
            state.status = "active"
            record = ResumeRecord(
                cron_id=cron_id,
                seq=seq,
                digest=_pin("resumed", cron_id, seq),
            )
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_RESUMED, {"cron_id": cron_id}, seq
                )
            )
            return record

    def cancel(self, cron_id: str, seq: int, reason: str = "manual") -> CancelRecord:
        """Terminally cancel a schedule. The id is retired forever."""
        with self._lock:
            self._bump(seq)
            state = self._live(cron_id, seq)
            if reason not in _REASONS:
                self._reject(seq, "bad-reason", BadReasonError(reason))
            state.status = "cancelled"
            record = CancelRecord(
                cron_id=cron_id,
                reason=reason,
                seq=seq,
                digest=_pin("cancelled", cron_id, reason, seq),
            )
            self._audit.append(
                cron_scheduler_audit_event(
                    KIND_CANCELLED,
                    {"cron_id": cron_id, "reason": reason},
                    seq,
                )
            )
            return record

    def due(self, tick: int, seq: int) -> DueReport:
        """Sweep one logical tick.

        Books a ``FireRecord`` (source ``due``) for every active,
        budget-fresh job whose expression matches ``tick``. When the
        host skipped fire points (``last_swept_tick`` lag), the missed
        count is booked as ``misfired`` data on the fire record plus a
        ``cron.misfired`` audit row — the job still fires once at this
        tick (catch-up-once policy).
        """
        with self._lock:
            self._bump(seq)
            tick = _check_tick(tick)
            entries: List[DueEntry] = []
            for cron_id in sorted(self._jobs):
                state = self._jobs[cron_id]
                if state.status != "active" or state.disabled:
                    continue
                expr = state.expr
                misfired = 0
                if state.last_swept_tick >= 0:
                    # Count scheduled ticks the host never swept, within a
                    # bounded lookback so epoch-scale ticks stay cheap.
                    # The first sweep only establishes the baseline.
                    swept_from = state.last_swept_tick + 1
                    window_from = max(
                        swept_from, tick - MISFIRE_LOOKBACK_TICKS
                    )
                    for t in range(window_from, tick):
                        if expr.matches(t):
                            misfired += 1
                state.last_swept_tick = tick
                if not expr.matches(tick):
                    if misfired:
                        self._audit.append(
                            cron_scheduler_audit_event(
                                KIND_MISFIRED,
                                {"cron_id": cron_id, "misfired": misfired},
                                seq,
                            )
                        )
                    continue
                state.fires += 1
                if (
                    state.record.max_fires
                    and state.fires >= state.record.max_fires
                ):
                    state.disabled = True
                fire = self._book_fire(
                    cron_id, SOURCE_DUE, VERDICT_FIRED, misfired, seq,
                    state.fires,
                )
                if misfired:
                    self._audit.append(
                        cron_scheduler_audit_event(
                            KIND_MISFIRED,
                            {
                                "cron_id": cron_id,
                                "misfired": misfired,
                                "fire_digest": fire.digest,
                            },
                            seq,
                        )
                    )
                entries.append(
                    DueEntry(
                        cron_id=cron_id,
                        fired=True,
                        misfired=misfired,
                        digest=_pin(
                            "due-entry", cron_id, True, misfired
                        ),
                    )
                )
            report = DueReport(
                tick=tick,
                entries=tuple(entries),
                seq=seq,
                digest=_pin(
                    "due", tick, [e.digest for e in entries], seq
                ),
            )
            return report

    # -- pure read views ------------------------------------------------

    def schedule_record(self, cron_id: str) -> ScheduleRecord:
        """The booked schedule (raises on unknown; never consumes seq)."""
        with self._lock:
            cron_id = _check_cron_id(cron_id)
            state = self._jobs.get(cron_id)
            if state is None:
                raise UnknownCronError(cron_id)
            return state.record

    def schedule_ids(self) -> Tuple[str, ...]:
        """All booked cron ids, sorted."""
        with self._lock:
            return tuple(sorted(self._jobs))

    def status(self, cron_id: str) -> str:
        """active | paused | cancelled (raises on unknown)."""
        with self._lock:
            cron_id = _check_cron_id(cron_id)
            state = self._jobs.get(cron_id)
            if state is None:
                raise UnknownCronError(cron_id)
            return state.status

    def fire_count(self, cron_id: str) -> int:
        """Booked fires for a cron id (raises on unknown)."""
        with self._lock:
            cron_id = _check_cron_id(cron_id)
            state = self._jobs.get(cron_id)
            if state is None:
                raise UnknownCronError(cron_id)
            return state.fires

    def fires(self) -> Tuple[FireRecord, ...]:
        """All booked fire records, oldest first."""
        with self._lock:
            return tuple(self._fires)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> Dict[str, int]:
        """Ledger counts."""
        with self._lock:
            return {
                "schedules": len(self._jobs),
                "active": sum(
                    1 for s in self._jobs.values() if s.status == "active"
                ),
                "paused": sum(
                    1 for s in self._jobs.values() if s.status == "paused"
                ),
                "cancelled": sum(
                    1
                    for s in self._jobs.values()
                    if s.status == "cancelled"
                ),
                "fires": len(self._fires),
                "audit_events": len(self._audit),
                "last_seq": self._last_seq,
            }


def main() -> None:
    """Self-check: schedule, trigger, pause/resume, due, cancel, audit."""
    cs = CronScheduler()
    rec = cs.schedule("hourly", "0 * * * *", 1)
    assert rec.verify() and rec.expr_digest.startswith(_DIGEST_PREFIX)
    fire = cs.trigger("hourly", 2)
    assert fire.verify() and fire.verdict == VERDICT_FIRED
    assert fire.source == SOURCE_TRIGGER
    cs.pause("hourly", 3)
    assert cs.status("hourly") == "paused"
    skipped = cs.trigger("hourly", 4)
    assert skipped.verdict == VERDICT_PAUSED
    cs.resume("hourly", 5)
    # Tick sweep: 2021-01-01T00:00:00Z fires "0 * * * *".
    report = cs.due(1609459200, 6)
    assert report.verify() and len(report.entries) == 1
    entry = report.entries[0]
    assert entry.fired and entry.misfired == 0 and entry.verify()
    cs.cancel("hourly", 7, "manual")
    assert cs.status("hourly") == "cancelled"
    try:
        cs.trigger("hourly", 8)
        raise AssertionError("trigger after cancel should fail")
    except CancelledCronError:
        pass
    kinds = [e["kind"] for e in cs.audit_log()]
    assert KIND_SCHEDULED in kinds and KIND_REJECTED in kinds
    assert cron_scheduler_audit_event(
        KIND_FIRED, {"cron_id": "x"}, 9
    )["schema"] == AUDIT_SCHEMA
    print(
        "cron-scheduler OK: schedule, trigger, pause, resume, due, "
        "cancel, pins, audit"
    )


if __name__ == "__main__":
    main()
