"""On-call rotation — PagerDuty-shaped schedule bookkeeping (thirty-fourth batch).

Research note (on-call literature): PagerDuty models on-call coverage
as schedule *layers*: an ordered participant list with a handoff
interval, plus temporary *overrides* that replace the layer for a
bounded window. Escalation policies consume the layer's "who is on
call" read view. The deterministic single-host intersection is:

* **Schedule layer**: ``schedule`` pins an ordered participant list
  and a shift length in logical seqs. The first participant is
  on-call; explicit ``handoff`` advances the roster round-robin and
  books a frozen ``HandoffRecord`` pinning the from/to pair.
* **Overrides**: ``override`` pins a bounded ``[start_seq, end_seq)``
  window where a named user replaces the layer; overlapping overrides
  on one rotation are refused fail-closed, and ``revoke_override``
  ends one early (terminal).
* **Read view**: ``current`` is a pure function over the ledger —
  the latest override covering ``at_seq`` wins, otherwise the layer's
  handoff-derived participant. No seq is consumed and nothing is
  audited for a read.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *who the schedule says* is on
call. It cannot page anyone, observe real incidents, or prove a human
picked up — user ids are opaque host-declared strings and paging is
the host's job. The read view pins the declared schedule, never wire
truth.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: Version pin for this module's record shape.
ONCALL_ROTATION_VERSION = "oncall-rotation.v1"

#: Schema pin carried by records and audit events.
ONCALL_ROTATION_SCHEMA = "northstar.oncall-rotation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ROTATION_CREATED = "oncall.rotation-created"
KIND_SCHEDULE_SET = "oncall.schedule-set"
KIND_HANDOFF = "oncall.handoff"
KIND_OVERRIDE_ADDED = "oncall.override-added"
KIND_OVERRIDE_REVOKED = "oncall.override-revoked"
KIND_REJECTED = "oncall.rejected"
_KINDS = (
    KIND_ROTATION_CREATED,
    KIND_SCHEDULE_SET,
    KIND_HANDOFF,
    KIND_OVERRIDE_ADDED,
    KIND_OVERRIDE_REVOKED,
    KIND_REJECTED,
)

#: Handoff reasons (pinned vocabulary).
REASON_MANUAL = "manual"
REASON_SCHEDULED = "scheduled"
REASON_INCIDENT = "incident"
REASON_ESCALATION = "escalation"
HANDOFF_REASONS = (
    REASON_MANUAL,
    REASON_SCHEDULED,
    REASON_INCIDENT,
    REASON_ESCALATION,
)

#: Bounds for participant lists and shifts (fail-closed sanity caps).
_MAX_PARTICIPANTS = 50

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OncallRotationError(ValueError):
    """Base error for the on-call rotation manager."""


class BadRotationError(OncallRotationError):
    """Malformed rotation id."""


class DuplicateRotationError(OncallRotationError):
    """This rotation id already exists."""


class UnknownRotationError(OncallRotationError):
    """No rotation with this id is registered."""


class BadParticipantError(OncallRotationError):
    """Malformed participant list or participant id."""


class DuplicateParticipantError(OncallRotationError):
    """A participant appears twice in the roster."""


class BadShiftError(OncallRotationError):
    """Shift length is not a positive int."""


class NoScheduleError(OncallRotationError):
    """This rotation has no schedule layer yet."""


class BadHandoffError(OncallRotationError):
    """Handoff reason is not in the pinned vocabulary."""


class BadOverrideError(OncallRotationError):
    """Malformed override window or user id."""


class OverlappingOverrideError(OncallRotationError):
    """This override window overlaps an active override."""


class UnknownOverrideError(OncallRotationError):
    """No override with this id exists on the rotation."""


class AlreadyRevokedError(OncallRotationError):
    """This override is already revoked."""


class SeqOrderError(OncallRotationError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OncallRotationError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OncallRotationError(
            f"{field_name} must be a non-empty string"
        )
    return value.strip()


def _check_participants(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise BadParticipantError(
            "participants must be a non-string sequence of user ids"
        )
    parts = tuple(_check_id(v, "participant") for v in value)
    if not 1 <= len(parts) <= _MAX_PARTICIPANTS:
        raise BadParticipantError(
            f"participants must have 1..{_MAX_PARTICIPANTS} entries, "
            f"saw {len(parts)}"
        )
    if len(set(parts)) != len(parts):
        raise DuplicateParticipantError(
            "participants contains a duplicate user id"
        )
    return parts


def _check_shift(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise BadShiftError(
            f"shift_length_seqs must be an int >= 1, saw {value!r}"
        )
    return value


def _check_reason(value: Any) -> str:
    if value not in HANDOFF_REASONS:
        raise BadHandoffError(
            f"reason must be one of {HANDOFF_REASONS}, saw {value!r}"
        )
    return value


def _check_window(start_seq: Any, end_seq: Any) -> tuple[int, int]:
    _check_seq(start_seq, "start_seq")
    _check_seq(end_seq, "end_seq")
    if end_seq <= start_seq:
        raise BadOverrideError(
            f"end_seq ({end_seq}) must be greater than start_seq ({start_seq})"
        )
    return start_seq, end_seq


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    # Payloads are str/int/bool/None/dict/list only — no floats, so no
    # >2^53 precision hazard; ints serialize exactly.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """sha256 hex pin over the canonical encoding of the parts."""
    return hashlib.sha256(_canonical(list(parts))).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RotationRecord:
    """One named on-call rotation (created before any schedule)."""

    rotation_id: str
    name: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.rotation_id, "rotation_id")
        _check_id(self.name, "name")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            ONCALL_ROTATION_VERSION,
            "rotation",
            self.rotation_id,
            self.name,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class ScheduleRecord:
    """One schedule layer: ordered roster + shift length.

    ``current_index`` is the roster position currently on-call
    (0 right after the layer is set); explicit ``handoff`` advances
    it round-robin. ``generation`` counts how many layers have been
    set on this rotation.
    """

    rotation_id: str
    participants: tuple[str, ...]
    shift_length_seqs: int
    generation: int
    current_index: int
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.rotation_id, "rotation_id")
        object.__setattr__(self, "participants", _check_participants(self.participants))
        _check_shift(self.shift_length_seqs)
        for name, value in (("generation", self.generation),
                            ("current_index", self.current_index)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise OncallRotationError(
                    f"{name} must be a non-negative int, saw {value!r}"
                )
        if self.current_index >= len(self.participants):
            raise OncallRotationError(
                f"current_index {self.current_index} out of range for "
                f"{len(self.participants)} participants"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            ONCALL_ROTATION_VERSION,
            "schedule",
            self.rotation_id,
            list(self.participants),
            self.shift_length_seqs,
            self.generation,
            self.current_index,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class HandoffRecord:
    """One explicit handoff: ``from_user`` → ``to_user``."""

    rotation_id: str
    from_user: str
    to_user: str
    reason: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.rotation_id, "rotation_id")
        _check_id(self.from_user, "from_user")
        _check_id(self.to_user, "to_user")
        _check_reason(self.reason)
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            ONCALL_ROTATION_VERSION,
            "handoff",
            self.rotation_id,
            self.from_user,
            self.to_user,
            self.reason,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class OverrideRecord:
    """One bounded override window.

    ``user_id`` replaces the layer for ``[start_seq, end_seq)``.
    ``revoked`` flips to True when the override is revoked early; a
    revoked override never participates in ``current``.
    """

    rotation_id: str
    override_id: str
    user_id: str
    start_seq: int
    end_seq: int
    revoked: bool
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_id(self.rotation_id, "rotation_id")
        _check_id(self.override_id, "override_id")
        _check_id(self.user_id, "user_id")
        _check_window(self.start_seq, self.end_seq)
        if not isinstance(self.revoked, bool):
            raise BadOverrideError(
                f"revoked must be a bool, saw {self.revoked!r}"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            ONCALL_ROTATION_VERSION,
            "override",
            self.rotation_id,
            self.override_id,
            self.user_id,
            self.start_seq,
            self.end_seq,
            self.revoked,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


def oncall_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for on-call rotation.

    Detail carries ids + digest pins only — no contact details exist
    in this module (user ids are opaque host-declared strings).
    """
    if kind not in _KINDS:
        raise OncallRotationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "oncall_rotation",
        "module_version": ONCALL_ROTATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# OncallRotation
# ---------------------------------------------------------------------------


class OncallRotation:
    """Deterministic PagerDuty-shaped on-call schedule bookkeeping.

    A rotation is created, given an ordered schedule layer
    (``schedule``), advanced explicitly via ``handoff``, and patched
    with bounded ``override`` windows. ``current`` resolves who the
    schedule says is on-call at any logical seq — the latest active
    override covering the seq wins, otherwise the layer's roster
    position. Mutation seqs must be strictly increasing; failed
    mutations consume their seq (batch-21 ledger discipline). No
    wall-clock, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._rotations: dict[str, RotationRecord] = {}
        self._schedules: dict[str, ScheduleRecord] = {}
        self._handoffs: dict[str, list[HandoffRecord]] = {}
        self._overrides: dict[str, list[OverrideRecord]] = {}
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq

    def _require_rotation(self, rotation_id: str, seq: int) -> None:
        rotation_id = _check_id(rotation_id, "rotation_id")
        if rotation_id not in self._rotations:
            self._reject(seq, rotation_id=rotation_id)
            raise UnknownRotationError(f"unknown rotation: {rotation_id!r}")
        return rotation_id

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(oncall_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, **detail)

    # -- mutations --------------------------------------------------------

    def create_rotation(
        self, rotation_id: str, name: str, seq: int
    ) -> RotationRecord:
        """Create a named on-call rotation (no schedule yet)."""
        with self._lock:
            self._claim_seq(seq)
            rotation_id = _check_id(rotation_id, "rotation_id")
            name = _check_id(name, "name")
            if rotation_id in self._rotations:
                self._reject(seq, rotation_id=rotation_id)
                raise DuplicateRotationError(
                    f"rotation already exists: {rotation_id!r}"
                )
            record = RotationRecord(
                rotation_id=rotation_id, name=name, seq=seq
            )
            self._rotations[rotation_id] = record
            self._handoffs[rotation_id] = []
            self._overrides[rotation_id] = []
            self._emit(
                KIND_ROTATION_CREATED,
                seq,
                rotation_id=rotation_id,
                name=name,
                digest=record.digest,
            )
            return record

    def schedule(
        self,
        rotation_id: str,
        participants: Sequence[str],
        shift_length_seqs: int,
        seq: int,
    ) -> ScheduleRecord:
        """Set (or replace) the rotation's schedule layer.

        The first participant is on-call immediately; explicit
        ``handoff`` advances the roster round-robin. Re-scheduling
        bumps the generation and resets the on-call to the first
        participant.
        """
        with self._lock:
            self._claim_seq(seq)
            rotation_id = self._require_rotation(rotation_id, seq)
            try:
                participants = _check_participants(participants)
                _check_shift(shift_length_seqs)
            except OncallRotationError:
                self._reject(seq, rotation_id=rotation_id)
                raise
            prev = self._schedules.get(rotation_id)
            generation = 0 if prev is None else prev.generation + 1
            record = ScheduleRecord(
                rotation_id=rotation_id,
                participants=participants,
                shift_length_seqs=shift_length_seqs,
                generation=generation,
                current_index=0,
                seq=seq,
            )
            self._schedules[rotation_id] = record
            self._emit(
                KIND_SCHEDULE_SET,
                seq,
                rotation_id=rotation_id,
                generation=generation,
                participant_count=len(participants),
                on_call=participants[0],
                digest=record.digest,
            )
            return record

    def handoff(
        self, rotation_id: str, seq: int, reason: str = REASON_MANUAL
    ) -> HandoffRecord:
        """Advance the on-call to the next roster participant.

        Round-robin: index ``(i + 1) % n``. The reason pins to the
        handoff vocabulary; the from/to pair is booked frozen.
        """
        with self._lock:
            self._claim_seq(seq)
            rotation_id = self._require_rotation(rotation_id, seq)
            schedule = self._schedules.get(rotation_id)
            if schedule is None:
                self._reject(seq, rotation_id=rotation_id)
                raise NoScheduleError(
                    f"rotation {rotation_id!r} has no schedule layer"
                )
            try:
                reason = _check_reason(reason)
            except OncallRotationError:
                self._reject(seq, rotation_id=rotation_id)
                raise
            parts = schedule.participants
            from_user = parts[schedule.current_index]
            to_index = (schedule.current_index + 1) % len(parts)
            to_user = parts[to_index]
            record = HandoffRecord(
                rotation_id=rotation_id,
                from_user=from_user,
                to_user=to_user,
                reason=reason,
                seq=seq,
            )
            self._handoffs[rotation_id].append(record)
            self._schedules[rotation_id] = ScheduleRecord(
                rotation_id=rotation_id,
                participants=parts,
                shift_length_seqs=schedule.shift_length_seqs,
                generation=schedule.generation,
                current_index=to_index,
                seq=seq,
            )
            self._emit(
                KIND_HANDOFF,
                seq,
                rotation_id=rotation_id,
                from_user=from_user,
                to_user=to_user,
                handoff_reason=reason,
                digest=record.digest,
            )
            return record

    def override(
        self,
        rotation_id: str,
        override_id: str,
        user_id: str,
        start_seq: int,
        end_seq: int,
        seq: int,
    ) -> OverrideRecord:
        """Pin a bounded override: ``user_id`` covers ``[start_seq, end_seq)``.

        Overlapping windows on one rotation are refused fail-closed.
        Overrides may name any user id — PagerDuty lets a layer be
        covered by users outside the roster.
        """
        with self._lock:
            self._claim_seq(seq)
            rotation_id = self._require_rotation(rotation_id, seq)
            override_id = _check_id(override_id, "override_id")
            user_id = _check_id(user_id, "user_id")
            try:
                _check_window(start_seq, end_seq)
            except OncallRotationError:
                self._reject(seq, rotation_id=rotation_id)
                raise
            existing = self._overrides[rotation_id]
            if any(o.override_id == override_id for o in existing):
                self._reject(seq, rotation_id=rotation_id)
                raise OncallRotationError(
                    f"override already exists: {override_id!r}"
                )
            for o in existing:
                if o.revoked:
                    continue
                if start_seq < o.end_seq and o.start_seq < end_seq:
                    self._reject(
                        seq,
                        rotation_id=rotation_id,
                        conflict_with=o.override_id,
                    )
                    raise OverlappingOverrideError(
                        f"window [{start_seq}, {end_seq}) overlaps "
                        f"override {o.override_id!r}"
                    )
            record = OverrideRecord(
                rotation_id=rotation_id,
                override_id=override_id,
                user_id=user_id,
                start_seq=start_seq,
                end_seq=end_seq,
                revoked=False,
                seq=seq,
            )
            existing.append(record)
            self._emit(
                KIND_OVERRIDE_ADDED,
                seq,
                rotation_id=rotation_id,
                override_id=override_id,
                digest=record.digest,
            )
            return record

    def revoke_override(self, rotation_id: str, override_id: str, seq: int) -> OverrideRecord:
        """End an override early (terminal; the window stops covering)."""
        with self._lock:
            self._claim_seq(seq)
            rotation_id = self._require_rotation(rotation_id, seq)
            override_id = _check_id(override_id, "override_id")
            existing = self._overrides[rotation_id]
            idx = next(
                (i for i, o in enumerate(existing) if o.override_id == override_id),
                None,
            )
            if idx is None:
                self._reject(seq, rotation_id=rotation_id)
                raise UnknownOverrideError(
                    f"unknown override: {override_id!r}"
                )
            old = existing[idx]
            if old.revoked:
                self._reject(seq, rotation_id=rotation_id)
                raise AlreadyRevokedError(
                    f"override already revoked: {override_id!r}"
                )
            record = OverrideRecord(
                rotation_id=old.rotation_id,
                override_id=old.override_id,
                user_id=old.user_id,
                start_seq=old.start_seq,
                end_seq=old.end_seq,
                revoked=True,
                seq=seq,
            )
            existing[idx] = record
            self._emit(
                KIND_OVERRIDE_REVOKED,
                seq,
                rotation_id=rotation_id,
                override_id=override_id,
                digest=record.digest,
            )
            return record

    # -- views --------------------------------------------------------------

    def current(self, rotation_id: str, at_seq: int) -> str:
        """Who the schedule says is on-call at ``at_seq`` (pure view).

        The latest active override covering ``at_seq`` wins; otherwise
        the layer's handoff-derived roster position. No seq consumed,
        nothing audited.
        """
        with self._lock:
            rotation_id = _check_id(rotation_id, "rotation_id")
            if rotation_id not in self._rotations:
                raise UnknownRotationError(f"unknown rotation: {rotation_id!r}")
            _check_seq(at_seq, "at_seq")
            schedule = self._schedules.get(rotation_id)
            if schedule is None:
                raise NoScheduleError(
                    f"rotation {rotation_id!r} has no schedule layer"
                )
            covered = [
                o
                for o in self._overrides[rotation_id]
                if not o.revoked and o.start_seq <= at_seq < o.end_seq
            ]
            if covered:
                # Latest wins: the most recently booked override covering
                # the seq. Overlaps are refused at booking, so at most
                # one can cover any seq.
                return max(covered, key=lambda o: o.seq).user_id
            return schedule.participants[schedule.current_index]

    def schedule_record(self, rotation_id: str) -> ScheduleRecord:
        """The current schedule layer of a rotation."""
        with self._lock:
            _check_id(rotation_id, "rotation_id")
            schedule = self._schedules.get(rotation_id)
            if schedule is None:
                raise NoScheduleError(
                    f"rotation {rotation_id!r} has no schedule layer"
                )
            return schedule

    def rotation(self, rotation_id: str) -> RotationRecord:
        """The rotation's creation record."""
        with self._lock:
            _check_id(rotation_id, "rotation_id")
            if rotation_id not in self._rotations:
                raise UnknownRotationError(f"unknown rotation: {rotation_id!r}")
            return self._rotations[rotation_id]

    def handoffs(self, rotation_id: str) -> tuple[HandoffRecord, ...]:
        """All handoff records, oldest first."""
        with self._lock:
            _check_id(rotation_id, "rotation_id")
            if rotation_id not in self._rotations:
                raise UnknownRotationError(f"unknown rotation: {rotation_id!r}")
            return tuple(self._handoffs[rotation_id])

    def overrides(self, rotation_id: str) -> tuple[OverrideRecord, ...]:
        """All override records (active and revoked), oldest first."""
        with self._lock:
            _check_id(rotation_id, "rotation_id")
            if rotation_id not in self._rotations:
                raise UnknownRotationError(f"unknown rotation: {rotation_id!r}")
            return tuple(self._overrides[rotation_id])

    def rotation_ids(self) -> tuple[str, ...]:
        """Registered rotation ids, sorted."""
        with self._lock:
            return tuple(sorted(self._rotations))

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Booked audit events, oldest first (ids + pins only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: create, schedule, handoff, override, current view."""
    mgr = OncallRotation()
    r = mgr.create_rotation("infra", "Infra primary", seq=1)
    assert r.verify() and r.rotation_id == "infra"
    s = mgr.schedule("infra", ["alice", "bob", "carol"], 48, seq=2)
    assert s.verify() and s.generation == 0 and s.current_index == 0
    assert mgr.current("infra", at_seq=5) == "alice"
    # Explicit handoffs advance round-robin and pin the from/to pair.
    h1 = mgr.handoff("infra", seq=3)
    assert h1.verify() and h1.from_user == "alice" and h1.to_user == "bob"
    assert h1.reason == "manual"
    h2 = mgr.handoff("infra", seq=4, reason="incident")
    assert h2.to_user == "carol" and h2.reason == "incident"
    assert mgr.current("infra", at_seq=10) == "carol"
    # Wrap-around.
    h3 = mgr.handoff("infra", seq=5)
    assert h3.from_user == "carol" and h3.to_user == "alice"
    assert mgr.current("infra", at_seq=10) == "alice"
    # Override wins over the layer while it covers the seq.
    ov = mgr.override("infra", "ov-1", "dave", start_seq=8, end_seq=12, seq=6)
    assert ov.verify() and not ov.revoked
    assert mgr.current("infra", at_seq=9) == "dave"
    assert mgr.current("infra", at_seq=7) == "alice"   # before window
    assert mgr.current("infra", at_seq=12) == "alice"  # after window
    # Overlap refused; revocation restores the layer.
    try:
        mgr.override("infra", "ov-2", "erin", start_seq=10, end_seq=20, seq=7)
    except OverlappingOverrideError:
        pass
    else:
        raise AssertionError("expected OverlappingOverrideError")
    rv = mgr.revoke_override("infra", "ov-1", seq=8)
    assert rv.verify() and rv.revoked
    assert mgr.current("infra", at_seq=9) == "alice"
    # Pins re-derive identically on a fresh instance with same inputs.
    other = OncallRotation()
    other.create_rotation("infra", "Infra primary", seq=1)
    other.schedule("infra", ["alice", "bob", "carol"], 48, seq=2)
    assert other.schedule_record("infra").digest == s.digest
    print("oncall-rotation OK: create, schedule, handoff, override, current, pins, audit")


if __name__ == "__main__":
    main()
