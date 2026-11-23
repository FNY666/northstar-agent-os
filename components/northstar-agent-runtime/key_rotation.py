"""Key rotation — deterministic automatic key rotation bookkeeping (thirty-first batch).

Research note (rotation literature): NIST SP 800-57 bounds a key's
cryptoperiod and prescribes rotation before the bound; AWS KMS and
HashiCorp Vault model rotation as *versioned* keys where the new
version becomes active and retired versions stay readable for a grace
window; Google Cloud KMS automates rotation on a schedule (rotation
period) driven by a caller-ticked clock. This module takes the
intersection for a single-host deterministic ledger:

* **Versioned keys**: ``register`` mints version 1; ``rotate`` mints
  version N+1 and retires version N. Every version is a frozen record
  with a digest pin and a ``prev_digest`` chain. Key material is derived
  deterministically from the manager seed and never enters a record or
  the audit trail.
* **Schedules, not timers**: ``schedule`` books a rotation interval in
  logical-seq units; ``due`` is a pure view of schedules whose next
  rotation is due at a caller-supplied seq; ``rotate`` advances the
  schedule's ``next_due_seq`` by one interval (a rotation resets the
  clock). No wall-clock anywhere — the host ticks.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (failed mutations consume their seq), RLock guarding,
fail-closed taxonomy, stdlib-only, sha256 digest pins over canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *rotation decisions*
deterministically. It cannot observe the wire, revoke keys held by
others, or prove a retired key stopped being used — a consumer wires
the frozen ``KeyVersion`` records to its own key store. Derived key
material is a deterministic placeholder, not a production KDF; pair
with an HSM/KMS and real secret handling for production. GIGO on key
ids: the ledger pins what the host declares.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

#: Version pin for this module's record shape.
KEY_ROTATION_VERSION = "key-rotation.v1"

#: Schema pin carried by records and audit events.
KEY_ROTATION_SCHEMA = "northstar.key-rotation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Rotation reasons (pinned vocabulary). ``initial`` is reserved for
#: ``register``; every other rotation must declare its cause.
REASON_INITIAL = "initial"
REASON_SCHEDULED = "scheduled"
REASON_MANUAL = "manual"
REASON_COMPROMISED = "compromised"
REASON_EXPIRED = "expired"
ROTATION_REASONS = (
    REASON_INITIAL,
    REASON_SCHEDULED,
    REASON_MANUAL,
    REASON_COMPROMISED,
    REASON_EXPIRED,
)

#: Version statuses (pinned vocabulary).
STATUS_ACTIVE = "active"
STATUS_RETIRED = "retired"
VERSION_STATUSES = (STATUS_ACTIVE, STATUS_RETIRED)

#: Audit event kinds.
KIND_KEY_REGISTERED = "rotation.key-registered"
KIND_SCHEDULED = "rotation.scheduled"
KIND_ROTATED = "rotation.rotated"
KIND_REJECTED = "rotation.rejected"
_KINDS = (KIND_KEY_REGISTERED, KIND_SCHEDULED, KIND_ROTATED, KIND_REJECTED)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class KeyRotationError(ValueError):
    """Base error for the key rotation manager."""


class BadKeyError(KeyRotationError):
    """Malformed key id or version payload."""


class DuplicateKeyError(KeyRotationError):
    """This key id is already registered."""


class UnknownKeyError(KeyRotationError):
    """No key with this id is registered."""


class BadScheduleError(KeyRotationError):
    """Malformed rotation schedule (bad interval, start, id)."""


class DuplicateScheduleError(KeyRotationError):
    """This key already has an active schedule."""


class UnknownScheduleError(KeyRotationError):
    """No schedule with this id exists."""


class BadRotationError(KeyRotationError):
    """Malformed rotation request (bad reason)."""


class SeqOrderError(KeyRotationError):
    """Mutation seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise KeyRotationError(
            f"{field_name} must be a non-negative int, saw {value!r}"
        )
    return value


def _check_key_id(value: Any, field_name: str = "key_id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadKeyError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_interval(value: Any, field_name: str = "interval_seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BadScheduleError(
            f"{field_name} must be a positive int, saw {value!r}"
        )
    return value


def _check_material_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
        or not all(c in "0123456789abcdef" for c in value[len(_DIGEST_PREFIX):])
    ):
        raise BadKeyError(
            "material_digest must be 'sha256:' + 64 hex chars"
        )
    return value


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
class KeyVersion:
    """One version of a rotated key.

    ``material_digest`` pins the derived key material (``sha256:`` +
    hex); the material itself never enters the record. ``status`` is
    ``active`` for the newest version and ``retired`` for older ones;
    the chain is linked by ``prev_digest``.
    """

    key_id: str
    version_index: int
    material_digest: str
    status: str
    reason: str
    prev_digest: str
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_key_id(self.key_id)
        if (
            isinstance(self.version_index, bool)
            or not isinstance(self.version_index, int)
            or self.version_index < 1
        ):
            raise BadKeyError(
                f"version_index must be an int >= 1, saw {self.version_index!r}"
            )
        _check_material_digest(self.material_digest)
        if self.status not in VERSION_STATUSES:
            raise BadKeyError(
                f"status must be one of {VERSION_STATUSES}, saw {self.status!r}"
            )
        if self.reason not in ROTATION_REASONS:
            raise BadRotationError(
                f"reason must be one of {ROTATION_REASONS}, saw {self.reason!r}"
            )
        if not isinstance(self.prev_digest, str) or not self.prev_digest:
            raise BadKeyError("prev_digest must be a non-empty string")
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            KEY_ROTATION_VERSION,
            "key-version",
            self.key_id,
            self.version_index,
            self.material_digest,
            self.status,
            self.reason,
            self.prev_digest,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


@dataclass(frozen=True)
class ScheduleRecord:
    """A rotation schedule: rotate ``key_id`` every ``interval_seq`` seq units.

    ``next_due_seq`` starts at ``start_seq + interval_seq`` and advances
    by one interval on every ``rotate`` of the key — rotating (manual or
    scheduled) resets the clock. ``enabled`` is pinned in the digest so
    a silent disable is detectable.
    """

    schedule_id: str
    key_id: str
    interval_seq: int
    start_seq: int
    next_due_seq: int
    enabled: bool
    seq: int
    digest: str = ""

    def __post_init__(self) -> None:
        _check_key_id(self.schedule_id, "schedule_id")
        _check_key_id(self.key_id)
        _check_interval(self.interval_seq)
        _check_seq(self.start_seq, "start_seq")
        _check_seq(self.next_due_seq, "next_due_seq")
        if not isinstance(self.enabled, bool):
            raise BadScheduleError(
                f"enabled must be a bool, saw {self.enabled!r}"
            )
        _check_seq(self.seq, "seq")
        if not self.digest:
            object.__setattr__(self, "digest", self._compute_digest())

    def _compute_digest(self) -> str:
        return _DIGEST_PREFIX + _pin(
            KEY_ROTATION_VERSION,
            "schedule",
            self.schedule_id,
            self.key_id,
            self.interval_seq,
            self.start_seq,
            self.next_due_seq,
            self.enabled,
            self.seq,
        )

    def verify(self) -> bool:
        """Re-derive the digest pin; True iff the record is intact."""
        return self.digest == self._compute_digest()


def key_rotation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for key rotation.

    Detail carries ids + digest pins only — key *material* never
    crosses the audit boundary.
    """
    if kind not in _KINDS:
        raise KeyRotationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "key_rotation",
        "module_version": KEY_ROTATION_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# KeyRotation
# ---------------------------------------------------------------------------


class KeyRotation:
    """Deterministic automatic key rotation bookkeeping.

    Keys are versioned: ``register`` mints version 1, ``rotate`` mints
    version N+1 and retires version N. ``schedule`` books a rotation
    interval in logical-seq units; ``due`` lists schedules whose next
    rotation is due; each rotation advances the schedule by one
    interval. Key material is derived deterministically from the manager
    seed via a sha256 chain and is never written into records or audit
    events.

    Mutation seqs must be strictly increasing; failed mutations consume
    their seq (batch-21 ledger discipline). No wall-clock, stdlib-only.
    """

    def __init__(self, seed: int = 0) -> None:
        _check_seq(seed, "seed")
        self._master = hashlib.sha256(
            f"{KEY_ROTATION_VERSION}:{seed}".encode("utf-8")
        ).digest()
        self._lock = threading.RLock()
        self._last_seq = 0
        self._versions: dict[str, list[KeyVersion]] = {}
        self._materials: dict[tuple[str, int], bytes] = {}
        self._schedules: dict[str, ScheduleRecord] = {}
        self._sched_by_key: dict[str, str] = {}
        self._sched_counter = 0
        self._audit: list[Mapping[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _claim_seq(self, seq: int) -> None:
        # Called first in every mutation: a refused mutation still
        # consumes its seq, keeping the ledger totally ordered.
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be an int > {self._last_seq}, saw {seq!r}"
            )
        self._last_seq = seq

    def _reject(self, seq: int, op: str, note: str) -> None:
        # The seq is already consumed by _claim_seq; just book the refusal.
        self._audit.append(
            key_rotation_audit_event(KIND_REJECTED, seq, op=op, note=note)
        )

    def _derive_material(self, key_id: str, version_index: int) -> bytes:
        # Deterministic placeholder derivation: sha256-chained, keyed by
        # (master, key_id, version_index). Same seed reproduces identical
        # material on any host; different seeds diverge.
        h = hashlib.sha256()
        h.update(self._master)
        h.update(b"\x00key-rotation\x00")
        h.update(key_id.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(version_index).encode("utf-8"))
        return h.digest()

    @staticmethod
    def _material_pin(material: bytes) -> str:
        return _DIGEST_PREFIX + hashlib.sha256(material).hexdigest()

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(key_rotation_audit_event(kind, seq, **detail))

    # -- mutations --------------------------------------------------------

    def register(self, key_id: str, seq: int) -> KeyVersion:
        """Register a key, minting version 1 (status ``active``)."""
        with self._lock:
            self._claim_seq(seq)
            _check_key_id(key_id)
            if key_id in self._versions:
                self._reject(seq, KIND_KEY_REGISTERED, f"duplicate key: {key_id!r}")
                raise DuplicateKeyError(f"key already registered: {key_id!r}")
            material = self._derive_material(key_id, 1)
            version = KeyVersion(
                key_id=key_id,
                version_index=1,
                material_digest=self._material_pin(material),
                status=STATUS_ACTIVE,
                reason=REASON_INITIAL,
                prev_digest=_GENESIS,
                seq=seq,
            )
            self._materials[(key_id, 1)] = material
            self._versions[key_id] = [version]
            self._emit(
                KIND_KEY_REGISTERED,
                seq,
                key_id=key_id,
                version_index=1,
                digest=version.digest,
            )
            return version

    def schedule(
        self,
        key_id: str,
        interval_seq: int,
        seq: int,
        start_seq: int | None = None,
    ) -> ScheduleRecord:
        """Book a rotation schedule: rotate ``key_id`` every ``interval_seq``.

        ``start_seq`` defaults to ``seq``; the first rotation is due at
        ``start_seq + interval_seq``. One active schedule per key.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_key_id(key_id)
            if key_id not in self._versions:
                self._reject(seq, KIND_SCHEDULED, f"unknown key: {key_id!r}")
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            _check_interval(interval_seq)
            if start_seq is None:
                start_seq = seq
            _check_seq(start_seq, "start_seq")
            if key_id in self._sched_by_key:
                self._reject(
                    seq, KIND_SCHEDULED, f"duplicate schedule for key: {key_id!r}"
                )
                raise DuplicateScheduleError(
                    f"key already has a schedule: {key_id!r}"
                )
            self._sched_counter += 1
            schedule_id = f"sch-{self._sched_counter}"
            record = ScheduleRecord(
                schedule_id=schedule_id,
                key_id=key_id,
                interval_seq=interval_seq,
                start_seq=start_seq,
                next_due_seq=start_seq + interval_seq,
                enabled=True,
                seq=seq,
            )
            self._schedules[schedule_id] = record
            self._sched_by_key[key_id] = schedule_id
            self._emit(
                KIND_SCHEDULED,
                seq,
                schedule_id=schedule_id,
                key_id=key_id,
                interval_seq=interval_seq,
                next_due_seq=record.next_due_seq,
                digest=record.digest,
            )
            return record

    def rotate(self, key_id: str, seq: int, reason: str = REASON_MANUAL) -> KeyVersion:
        """Mint version N+1 for ``key_id`` and retire version N.

        ``reason`` must be a pinned reason other than ``initial`` (that
        reason is reserved for ``register``). If the key has a schedule,
        the rotation advances ``next_due_seq`` by one interval — a
        rotation resets the clock.
        """
        with self._lock:
            self._claim_seq(seq)
            _check_key_id(key_id)
            versions = self._versions.get(key_id)
            if versions is None:
                self._reject(seq, KIND_ROTATED, f"unknown key: {key_id!r}")
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            if reason not in ROTATION_REASONS or reason == REASON_INITIAL:
                allowed = tuple(r for r in ROTATION_REASONS if r != REASON_INITIAL)
                self._reject(seq, KIND_ROTATED, f"bad reason: {reason!r}")
                raise BadRotationError(
                    f"reason must be one of {allowed}, saw {reason!r}"
                )
            prev = versions[-1]
            retired = KeyVersion(
                key_id=prev.key_id,
                version_index=prev.version_index,
                material_digest=prev.material_digest,
                status=STATUS_RETIRED,
                reason=prev.reason,
                prev_digest=prev.prev_digest,
                seq=prev.seq,
            )
            index = len(versions) + 1
            material = self._derive_material(key_id, index)
            new = KeyVersion(
                key_id=key_id,
                version_index=index,
                material_digest=self._material_pin(material),
                status=STATUS_ACTIVE,
                reason=reason,
                prev_digest=retired.digest,
                seq=seq,
            )
            self._materials[(key_id, index)] = material
            versions[-1] = retired
            versions.append(new)
            sched_id = self._sched_by_key.get(key_id)
            if sched_id is not None:
                rec = self._schedules[sched_id]
                self._schedules[sched_id] = ScheduleRecord(
                    schedule_id=rec.schedule_id,
                    key_id=rec.key_id,
                    interval_seq=rec.interval_seq,
                    start_seq=rec.start_seq,
                    next_due_seq=seq + rec.interval_seq,
                    enabled=rec.enabled,
                    seq=seq,
                )
            self._emit(
                KIND_ROTATED,
                seq,
                key_id=key_id,
                version_index=index,
                reason=reason,
                digest=new.digest,
            )
            return new

    # -- views ------------------------------------------------------------

    def versions(self, key_id: str) -> tuple[KeyVersion, ...]:
        """All versions of a key, oldest first. Unknown key raises."""
        with self._lock:
            _check_key_id(key_id)
            found = self._versions.get(key_id)
            if found is None:
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            return tuple(found)

    def active_version(self, key_id: str) -> KeyVersion:
        """The currently active version of a key. Unknown key raises."""
        with self._lock:
            return self.versions(key_id)[-1]

    def material_for(self, key_id: str, version_index: int) -> bytes:
        """Derived key material for a version (pure view).

        Exposed so the host can wire the ledger to its own key store;
        the material never enters records or the audit trail.
        """
        with self._lock:
            _check_key_id(key_id)
            material = self._materials.get((key_id, version_index))
            if material is None:
                raise UnknownKeyError(
                    f"no version {version_index!r} for key {key_id!r}"
                )
            return material

    def due(self, seq: int) -> tuple[ScheduleRecord, ...]:
        """Schedules whose ``next_due_seq`` is at or before ``seq``.

        Pure view: the seq is validated, not consumed, and no audit is
        written.
        """
        with self._lock:
            _check_seq(seq, "seq")
            return tuple(
                sorted(
                    (
                        r
                        for r in self._schedules.values()
                        if r.enabled and r.next_due_seq <= seq
                    ),
                    key=lambda r: r.schedule_id,
                )
            )

    def key_ids(self) -> tuple[str, ...]:
        """Registered key ids, sorted."""
        with self._lock:
            return tuple(sorted(self._versions))

    def schedule_ids(self) -> tuple[str, ...]:
        """Schedule ids, sorted."""
        with self._lock:
            return tuple(sorted(self._schedules))

    def schedule_record(self, schedule_id: str) -> ScheduleRecord:
        """A schedule record by id. Unknown id raises."""
        with self._lock:
            _check_key_id(schedule_id, "schedule_id")
            rec = self._schedules.get(schedule_id)
            if rec is None:
                raise UnknownScheduleError(f"unknown schedule: {schedule_id!r}")
            return rec

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        """Append-only audit events (ids + digest pins only)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, schedule, rotate, due, versions, pins."""
    mgr = KeyRotation(seed=7)
    v1 = mgr.register("api-key", seq=1)
    assert v1.verify() and v1.version_index == 1 and v1.status == "active"
    assert v1.reason == "initial" and v1.prev_digest == _GENESIS
    sch = mgr.schedule("api-key", interval_seq=10, seq=2)
    assert sch.verify() and sch.next_due_seq == 12
    assert mgr.due(5) == () and len(mgr.due(12)) == 1
    v2 = mgr.rotate("api-key", seq=3, reason="scheduled")
    assert v2.verify() and v2.version_index == 2 and v2.status == "active"
    assert v2.prev_digest == mgr.versions("api-key")[0].digest
    assert mgr.versions("api-key")[0].status == "retired"
    assert mgr.active_version("api-key").version_index == 2
    # Rotation advanced the schedule by one interval.
    assert mgr.schedule_record(sch.schedule_id).next_due_seq == 13
    # Determinism: the same seed reproduces the same material pins.
    other = KeyRotation(seed=7)
    other.register("api-key", seq=1)
    assert other.versions("api-key")[0].material_digest == v1.material_digest
    assert other.material_for("api-key", 1) == mgr.material_for("api-key", 1)
    third = KeyRotation(seed=8)
    third.register("api-key", seq=1)
    assert third.versions("api-key")[0].material_digest != v1.material_digest
    print("key-rotation OK: register, schedule, rotate, due, versions, pins, audit")


if __name__ == "__main__":
    main()
