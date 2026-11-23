"""On-call scheduler: rotation schedules, who-is-oncall, handoff bookkeeping (simulated).

Research note: on-call rotation is the operational discipline behind
PagerDuty, OpsGenie, and VictorOps — a *rotation* is an ordered roster of
responders who take turns holding the pager for fixed *shifts*. The
load-bearing properties are well studied (PagerDuty's "incident response"
guides; Google SRE Book ch. 29 "Managing Load"; the *follow-the-sun*
rotation pattern for global teams):

* **Shift assignment is a pure function of position** — given a start
  seq, a shift length, and an ordered roster, "who is oncall at seq T" is
  fully determined: ``members[(T - start) // shift_length % len(members)]``.
  No database round-trip, no ambiguity; two hosts that agree on the
  inputs agree on the answer (audit-replay exactness).
* **Handoff is an explicit, recorded override** — a mid-shift swap
  (someone trades a shift, someone escalates) never edits the schedule:
  it appends a frozen ``HandoffRecord`` pinned to the shift it overrides.
  The schedule stays the source of truth; overrides are a ledger layered
  on top, so the *intended* and the *actual* oncall are both auditable.
* **Fail-closed transitions** — a handoff from someone who is not the
  active oncall is refused (no silent no-op, no confusion about who was
  on duty); a handoff to the already-active member is refused for the
  same reason. ``who_is_oncall`` never returns ``None``: unknown
  rotations, missing schedules, and queries before the schedule start
  all raise.

Honest scope: this is the *bookkeeping layer* for a rotation, not a
paging system. It never contacts a human (no SMS, no phone call, no
push); ``who_is_oncall`` answers "who holds the pager at seq T as
reported", never "this person will actually pick up". It cannot prove
a human was reachable, cannot verify host-reported seqs advance, and
owns no real escalation policy beyond the roster order — pair with an
alerting pipeline for that half. Time is caller-supplied integer seqs
(logical ticks, e.g. minutes since epoch); there is no wall clock here.

The >2^53 JCS float-loss caveat documented in batch 5 applies to the
digest canonicalizer (shared ``canonical_json`` fallback): seqs are
ints and therefore type-tagged, so distinct integral seqs pin
distinctly, but a caller passing floats is rejected fail-closed before
any digest is computed.

Version pin: oncall-scheduler.v1
Schema pin: northstar.oncall-scheduler.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
ONCALL_SCHEDULER_VERSION = "oncall-scheduler.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.oncall-scheduler.v1"

#: Maximum members per rotation (guardrail, not a crypto parameter).
MAX_MEMBERS = 256

_AUDIT_KINDS = frozenset(
    {
        "rotation-created",
        "rotation-scheduled",
        "oncall-resolved",
        "handoff-recorded",
        "rejected",
    }
)


class OnCallSchedulerError(Exception):
    """Base class for all on-call scheduler failures."""


class UnknownRotationError(OnCallSchedulerError):
    """The rotation_id was never created."""


class DuplicateRotationError(OnCallSchedulerError):
    """create_rotation() on an already-existing rotation_id."""


class NoScheduleError(OnCallSchedulerError):
    """who_is_oncall() before schedule() was ever called for the rotation."""


class BeforeScheduleError(OnCallSchedulerError):
    """who_is_oncall() queried at a seq before the schedule's start_seq."""


class UnknownMemberError(OnCallSchedulerError):
    """A member name is not on the rotation roster."""


class HandoffError(OnCallSchedulerError):
    """A handoff transition was refused fail-closed."""


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise OnCallSchedulerError(f"{what} must be a str")
    if not value:
        raise OnCallSchedulerError(f"{what} must be non-empty")
    return value


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise OnCallSchedulerError(f"{what} must be an int")
    if seq < 0:
        raise OnCallSchedulerError(f"{what} must be non-negative")
    return seq


def _check_member(member: Any) -> str:
    if isinstance(member, bool) or not isinstance(member, str):
        raise OnCallSchedulerError("member names must be str")
    if not member:
        raise OnCallSchedulerError("member names must be non-empty")
    return member


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


@dataclass(frozen=True)
class RotationRecord:
    """Frozen record of a created rotation."""

    rotation_id: str
    members: Tuple[str, ...]
    created_seq: int
    digest: str
    version: str = ONCALL_SCHEDULER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rotation_id": self.rotation_id,
            "members": list(self.members),
            "created_seq": self.created_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ScheduleRecord:
    """Frozen record of a rotation's shift schedule."""

    rotation_id: str
    shift_length_seqs: int
    start_seq: int
    scheduled_seq: int
    digest: str
    version: str = ONCALL_SCHEDULER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rotation_id": self.rotation_id,
            "shift_length_seqs": self.shift_length_seqs,
            "start_seq": self.start_seq,
            "scheduled_seq": self.scheduled_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class HandoffRecord:
    """Frozen record of one mid-shift handoff override."""

    rotation_id: str
    shift_index: int
    from_member: str
    to_member: str
    effective_seq: int
    recorded_seq: int
    digest: str
    version: str = ONCALL_SCHEDULER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rotation_id": self.rotation_id,
            "shift_index": self.shift_index,
            "from_member": self.from_member,
            "to_member": self.to_member,
            "effective_seq": self.effective_seq,
            "recorded_seq": self.recorded_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class OnCallResult:
    """Frozen answer to "who is oncall at seq T"."""

    rotation_id: str
    at_seq: int
    shift_index: int
    shift_start: int
    shift_end: int
    scheduled_member: str
    active_member: str
    handoff_applied: bool
    digest: str
    version: str = ONCALL_SCHEDULER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rotation_id": self.rotation_id,
            "at_seq": self.at_seq,
            "shift_index": self.shift_index,
            "shift_start": self.shift_start,
            "shift_end": self.shift_end,
            "scheduled_member": self.scheduled_member,
            "active_member": self.active_member,
            "handoff_applied": self.handoff_applied,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class OnCallScheduler:
    """Rotation roster + shift schedule + handoff ledger (RLock-guarded)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._members: Dict[str, Tuple[str, ...]] = {}
        self._schedules: Dict[str, ScheduleRecord] = {}
        self._handoffs: Dict[str, list] = {}

    # -- rotation lifecycle ------------------------------------------------

    def create_rotation(
        self, rotation_id: Any, members: Any, seq: Any
    ) -> RotationRecord:
        """Register a rotation roster. Members are ordered; order matters."""
        rid = _check_id(rotation_id, "rotation_id")
        s = _check_seq(seq)
        if not isinstance(members, (tuple, list)) or not members:
            raise OnCallSchedulerError("members must be a non-empty tuple/list")
        roster = tuple(_check_member(m) for m in members)
        if len(roster) != len(set(roster)):
            raise OnCallSchedulerError("members must be unique")
        if len(roster) > MAX_MEMBERS:
            raise OnCallSchedulerError("too many members")
        with self._lock:
            if rid in self._members:
                raise DuplicateRotationError(f"rotation {rid!r} already exists")
            self._members[rid] = roster
            self._handoffs[rid] = []
            digest = _digest(
                {"rotation_id": rid, "members": list(roster), "seq": s}
            )
            return RotationRecord(
                rotation_id=rid, members=roster, created_seq=s, digest=digest
            )

    def schedule(
        self, rotation_id: Any, shift_length_seqs: Any, start_seq: Any, seq: Any
    ) -> ScheduleRecord:
        """Set the shift schedule: shifts of ``shift_length_seqs`` starting at ``start_seq``."""
        rid = _check_id(rotation_id, "rotation_id")
        s = _check_seq(seq)
        if isinstance(shift_length_seqs, bool) or not isinstance(
            shift_length_seqs, int
        ):
            raise OnCallSchedulerError("shift_length_seqs must be an int")
        if shift_length_seqs <= 0:
            raise OnCallSchedulerError("shift_length_seqs must be positive")
        st = _check_seq(start_seq, "start_seq")
        with self._lock:
            if rid not in self._members:
                raise UnknownRotationError(f"rotation {rid!r} unknown")
            record = ScheduleRecord(
                rotation_id=rid,
                shift_length_seqs=shift_length_seqs,
                start_seq=st,
                scheduled_seq=s,
                digest=_digest(
                    {
                        "rotation_id": rid,
                        "shift_length_seqs": shift_length_seqs,
                        "start_seq": st,
                        "seq": s,
                    }
                ),
            )
            self._schedules[rid] = record
            return record

    # -- resolution --------------------------------------------------------

    def _shift_index(self, rid: str, at_seq: int) -> Tuple[int, int, int]:
        sched = self._schedules.get(rid)
        if sched is None:
            raise NoScheduleError(f"rotation {rid!r} has no schedule")
        if at_seq < sched.start_seq:
            raise BeforeScheduleError(
                f"at_seq {at_seq} is before schedule start {sched.start_seq}"
            )
        idx = (at_seq - sched.start_seq) // sched.shift_length_seqs
        start = sched.start_seq + idx * sched.shift_length_seqs
        return idx, start, start + sched.shift_length_seqs

    def _active_at(self, rid: str, at_seq: int) -> Tuple[str, str, bool]:
        """Return (scheduled_member, active_member, handoff_applied) at at_seq."""
        idx, _, _ = self._shift_index(rid, at_seq)
        roster = self._members[rid]
        scheduled = roster[idx % len(roster)]
        applicable = [
            h
            for h in self._handoffs[rid]
            if h.shift_index == idx and h.effective_seq <= at_seq
        ]
        if applicable:
            latest = max(applicable, key=lambda h: h.effective_seq)
            return scheduled, latest.to_member, True
        return scheduled, scheduled, False

    def who_is_oncall(self, rotation_id: Any, at_seq: Any, seq: Any) -> OnCallResult:
        """Resolve who holds the pager at ``at_seq`` (never returns None)."""
        rid = _check_id(rotation_id, "rotation_id")
        t = _check_seq(at_seq, "at_seq")
        _check_seq(seq)
        with self._lock:
            if rid not in self._members:
                raise UnknownRotationError(f"rotation {rid!r} unknown")
            idx, start, end = self._shift_index(rid, t)
            scheduled, active, handoff_applied = self._active_at(rid, t)
            digest = _digest(
                {
                    "rotation_id": rid,
                    "at_seq": t,
                    "shift_index": idx,
                    "active_member": active,
                }
            )
            return OnCallResult(
                rotation_id=rid,
                at_seq=t,
                shift_index=idx,
                shift_start=start,
                shift_end=end,
                scheduled_member=scheduled,
                active_member=active,
                handoff_applied=handoff_applied,
                digest=digest,
            )

    # -- handoff -----------------------------------------------------------

    def handoff(
        self, rotation_id: Any, from_member: Any, to_member: Any, seq: Any
    ) -> HandoffRecord:
        """Record an explicit mid-shift handoff effective immediately.

        ``from_member`` must be the member currently active at ``seq``;
        ``to_member`` must be a different roster member. The schedule is
        never edited — the handoff is an override pinned to the shift.
        """
        rid = _check_id(rotation_id, "rotation_id")
        frm = _check_member(from_member)
        to = _check_member(to_member)
        s = _check_seq(seq)
        with self._lock:
            if rid not in self._members:
                raise UnknownRotationError(f"rotation {rid!r} unknown")
            if rid not in self._schedules:
                raise NoScheduleError(f"rotation {rid!r} has no schedule")
            roster = self._members[rid]
            if to not in roster:
                raise UnknownMemberError(f"to_member {to!r} not on roster")
            scheduled, active, _ = self._active_at(rid, s)
            if frm != active:
                raise HandoffError(
                    f"from_member {frm!r} is not the active oncall ({active!r})"
                )
            if to == active:
                raise HandoffError(
                    f"to_member {to!r} is already the active oncall"
                )
            idx, _, _ = self._shift_index(rid, s)
            record = HandoffRecord(
                rotation_id=rid,
                shift_index=idx,
                from_member=frm,
                to_member=to,
                effective_seq=s,
                recorded_seq=s,
                digest=_digest(
                    {
                        "rotation_id": rid,
                        "shift_index": idx,
                        "from_member": frm,
                        "to_member": to,
                        "seq": s,
                    }
                ),
            )
            self._handoffs[rid].append(record)
            return record

    # -- views -------------------------------------------------------------

    def rotations(self) -> Tuple[str, ...]:
        """Sorted rotation ids."""
        with self._lock:
            return tuple(sorted(self._members))

    def rotation(self, rotation_id: Any) -> RotationRecord:
        """Re-derive the rotation record (pins the current roster)."""
        rid = _check_id(rotation_id, "rotation_id")
        with self._lock:
            if rid not in self._members:
                raise UnknownRotationError(f"rotation {rid!r} unknown")
            roster = self._members[rid]
            return RotationRecord(
                rotation_id=rid,
                members=roster,
                created_seq=0,
                digest=_digest({"rotation_id": rid, "members": list(roster)}),
            )

    def schedule_info(self, rotation_id: Any) -> ScheduleRecord:
        """The rotation's current schedule record."""
        rid = _check_id(rotation_id, "rotation_id")
        with self._lock:
            if rid not in self._schedules:
                raise NoScheduleError(f"rotation {rid!r} has no schedule")
            return self._schedules[rid]

    def handoffs(self, rotation_id: Any) -> Tuple[HandoffRecord, ...]:
        """All handoff records for a rotation, in record order."""
        rid = _check_id(rotation_id, "rotation_id")
        with self._lock:
            if rid not in self._members:
                raise UnknownRotationError(f"rotation {rid!r} unknown")
            return tuple(self._handoffs[rid])


def oncall_scheduler_audit_event(kind: Any, seq: Any, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for an on-call scheduler event."""
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise OnCallSchedulerError(f"unknown audit kind: {kind!r}")
    s = _check_seq(seq)
    body = {"kind": kind, "seq": s, "version": ONCALL_SCHEDULER_VERSION}
    if detail:
        body["detail"] = {str(k): detail[k] for k in sorted(detail)}
    return {
        "schema": "audit.ndjson/1",
        "module": "oncall_scheduler",
        "event": body,
        "digest": _digest({"module": "oncall_scheduler", "kind": kind, "seq": s}),
    }


def main() -> None:
    sched = OnCallScheduler()
    sched.create_rotation("primary", ("alice", "bob", "carol"), 0)
    sched.schedule("primary", 7, 0, 1)
    first = sched.who_is_oncall("primary", 3, 2)
    assert first.active_member == "alice", first
    sched.handoff("primary", "alice", "bob", 4)
    swapped = sched.who_is_oncall("primary", 5, 3)
    assert swapped.active_member == "bob" and swapped.handoff_applied, swapped
    next_shift = sched.who_is_oncall("primary", 8, 4)
    assert next_shift.active_member == "bob" and not next_shift.handoff_applied, next_shift
    ev = oncall_scheduler_audit_event("handoff-recorded", 5, rotation="primary")
    assert ev["schema"] == "audit.ndjson/1"
    print("oncall-scheduler OK: rotation, schedule, handoff, resolution")


if __name__ == "__main__":
    main()
