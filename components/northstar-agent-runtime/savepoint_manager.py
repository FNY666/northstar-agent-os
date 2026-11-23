"""Flink savepoint lifecycle interface (simulated bookkeeping).

Research motivation: stream processors fail, and recovery must land on
a *consistent* global state. Flink's answer is the savepoint: a
manually triggered, full snapshot of operator state (each operator's
state keyed by its operator UID) that a job can later restore into.
The restore-time invariant that matters is *operator-UID compatibility*:
every operator recorded in the savepoint must map to an operator in the
job being restored; orphaned state (a savepoint operator with no
matching job operator) is refused unless the caller explicitly allows
it (Flink's ``--allowNonRestoredState`` flag, default false).

This module pins that *lifecycle bookkeeping*:

- ``SavepointManager`` -- owns the savepoint registry.
  - ``trigger(operator_states, seq)`` -- full snapshot. ``operator_states``
    is a mapping ``operator_uid -> state bytes``; every uid gets a
    ``sha256:`` state pin and the whole snapshot a ``sha256:`` savepoint
    digest. Returns a frozen ``SavepointHandle``.
  - ``restore(sp, seq, job_operator_uids=(), allow_unmapped_operators=False)``
    -- replays the pinned snapshot as a frozen ``RestoredSnapshot``.
    Every savepoint operator must appear in ``job_operator_uids`` unless
    ``allow_unmapped_operators`` is true; the digest re-pins before any
    byte is returned (corruption is fail-closed, never silently restored).
  - ``dispose(sp, seq)`` -- deletes the snapshot data from the registry;
    a disposed savepoint is unrecoverable (restore refuses).
- ``verify(sp_id)`` -- liveness + integrity check, returns a frozen
  ``SavepointHealth`` (never raises on an unhealthy savepoint; unknown
  ids are still fail-closed).
- ``list()`` -- live savepoints in creation order; ``info(sp_id)`` --
  the pinned record (state *pins*, never state bytes).
- ``savepoint_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``triggered`` / ``restored`` / ``disposed`` / ``rejected``);
  caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``operator_states`` must be a non-empty mapping with non-empty ``str``
  uids and ``bytes`` payloads; empty payloads are refused (an operator
  with nothing to restore is a caller bug); per-operator payload is
  capped at 1 MiB (a snapshot is a checkpoint, not a data dump).
- ``trigger`` seqs are monotonically enforced: a ``seq`` older than the
  last trigger is refused (savepoint ids are an append-only ledger;
  rewinding them would alias ids).
- ``restore`` of an unknown id raises ``UnknownSavepointError``; of a
  disposed id raises ``DisposedSavepointError``; digest mismatch raises
  ``IncompatibleSavepointError`` (corruption is a restore refusal, not a
  warning).
- ``dispose`` of an unknown id raises ``UnknownSavepointError``;
  disposing twice raises ``DisposedSavepointError`` (the data is gone;
  a second dispose cannot succeed).
- Caller-supplied seqs are ints (not bool), >= 0.

Honest scope:

- This module manages *reported* state bytes. It pins them, re-pins
  them on restore, and refuses corrupted records, but it cannot prove
  the bytes are *correct* operator state: a host that snapshots garbage
  gets garbage restored, digest-pinned and all.
- The registry is in-memory. ``dispose`` removes the bytes from the
  registry; deleting any durable copy of the savepoint data is the
  host's job.
- Bytes returned by ``restore`` are fresh copies: mutating a restored
  payload cannot move a pinned digest or corrupt the registry.
- Integer seqs are hex-encoded inside digest bodies (immune to the
  canonical-JSON ``>2**53`` float-loss caveat found in batch 5).
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
SAVEPOINT_MANAGER_VERSION = "savepoint-manager.v1"

#: Schema pin carried by records.
SAVEPOINT_MANAGER_SCHEMA = "northstar.savepoint-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Per-operator state payload guardrail: a savepoint is a checkpoint, not a dump.
MAX_STATE_BYTES = 1_048_576

#: Fixed audit-event vocabulary for savepoint_manager_audit_event.
AUDIT_KINDS = ("triggered", "restored", "disposed", "rejected")


class SavepointManagerError(Exception):
    """Base error for the savepoint manager (programming errors)."""


class UnknownSavepointError(SavepointManagerError):
    """Raised when a savepoint id names nothing in the registry."""


class DisposedSavepointError(SavepointManagerError):
    """Raised when an operation touches a disposed savepoint."""


class IncompatibleSavepointError(SavepointManagerError):
    """Raised when a savepoint fails restore-time integrity or UID checks."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_sp_id(value: object) -> str:
    """Validate a savepoint id: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"savepoint_id must be str, got {type(value).__name__}")
    if not value:
        raise ValueError("savepoint_id must be non-empty")
    return value


def _check_operator_states(value: object) -> Tuple[Tuple[str, bytes], ...]:
    """Validate a full operator-state snapshot: non-empty mapping of str->bytes."""
    if not isinstance(value, Mapping):
        raise TypeError(
            f"operator_states must be a mapping, got {type(value).__name__}"
        )
    if not value:
        raise ValueError("operator_states must not be empty")
    pairs = []
    for uid, payload in value.items():
        if not isinstance(uid, str):
            raise TypeError(
                f"operator uid must be str, got {type(uid).__name__}"
            )
        if not uid:
            raise ValueError("operator uid must be non-empty")
        if not isinstance(payload, bytes):
            raise TypeError(
                f"state payload for {uid!r} must be bytes, "
                f"got {type(payload).__name__}"
            )
        if not payload:
            raise ValueError(f"state payload for {uid!r} must not be empty")
        if len(payload) > MAX_STATE_BYTES:
            raise ValueError(
                f"state payload for {uid!r} exceeds {MAX_STATE_BYTES} bytes"
            )
        pairs.append((uid, payload))
    return tuple(sorted(pairs, key=lambda kv: kv[0]))


def _pin_state(payload: bytes) -> str:
    """Digest-pin one operator's state bytes."""
    return "sha256:" + hashlib.sha256(b"savepoint-manager.v1/state\x00" + payload).hexdigest()


def _pin_savepoint(savepoint_id: str, state_pins: Tuple[Tuple[str, str], ...],
                   created_seq: int) -> str:
    """Digest-pin the whole savepoint body (hex-encoded seq: >2**53-safe)."""
    body = {
        "savepoint_id": savepoint_id,
        "created_seq": "%x" % created_seq,
        "states": [{"operator_uid": uid, "state_pin": pin} for uid, pin in state_pins],
    }
    return "sha256:" + jcs_sha256_hex(body)


@dataclass(frozen=True)
class SavepointHandle:
    """Public handle returned by trigger()."""

    savepoint_id: str
    created_seq: int
    digest: str
    operator_uids: Tuple[str, ...]
    version: str = SAVEPOINT_MANAGER_VERSION
    schema: str = SAVEPOINT_MANAGER_SCHEMA

    def __post_init__(self) -> None:
        _check_sp_id(self.savepoint_id)
        _check_seq(self.created_seq, "created_seq")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        if not isinstance(self.operator_uids, tuple) or not self.operator_uids:
            raise TypeError("operator_uids must be a non-empty tuple")
        if self.version != SAVEPOINT_MANAGER_VERSION:
            raise ValueError("bad version pin")
        if self.schema != SAVEPOINT_MANAGER_SCHEMA:
            raise ValueError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "savepoint_id": self.savepoint_id,
            "created_seq": self.created_seq,
            "digest": self.digest,
            "operator_uids": list(self.operator_uids),
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RestoredSnapshot:
    """The restored operator-state snapshot (state *bytes* by copy)."""

    savepoint_id: str
    restore_seq: int
    states: Tuple[Tuple[str, bytes], ...]
    digest: str
    version: str = SAVEPOINT_MANAGER_VERSION
    schema: str = SAVEPOINT_MANAGER_SCHEMA

    def __post_init__(self) -> None:
        _check_sp_id(self.savepoint_id)
        _check_seq(self.restore_seq, "restore_seq")
        if not isinstance(self.states, tuple) or not self.states:
            raise TypeError("states must be a non-empty tuple")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        if self.version != SAVEPOINT_MANAGER_VERSION:
            raise ValueError("bad version pin")
        if self.schema != SAVEPOINT_MANAGER_SCHEMA:
            raise ValueError("bad schema pin")

    def state_for(self, operator_uid: str) -> Optional[bytes]:
        """Return the restored payload for one operator (copy), or None."""
        for uid, payload in self.states:
            if uid == operator_uid:
                return bytes(payload)
        return None

    def as_dict(self) -> dict:
        return {
            "savepoint_id": self.savepoint_id,
            "restore_seq": self.restore_seq,
            "operators": [
                {"operator_uid": uid, "state_pin": _pin_state(payload)}
                for uid, payload in self.states
            ],
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DisposalRecord:
    """Receipt for a dispose() call."""

    savepoint_id: str
    dispose_seq: int
    operator_count: int
    digest: str
    version: str = SAVEPOINT_MANAGER_VERSION
    schema: str = SAVEPOINT_MANAGER_SCHEMA

    def __post_init__(self) -> None:
        _check_sp_id(self.savepoint_id)
        _check_seq(self.dispose_seq, "dispose_seq")
        if isinstance(self.operator_count, bool) or not isinstance(self.operator_count, int):
            raise TypeError("operator_count must be int")
        if self.operator_count <= 0:
            raise ValueError("operator_count must be positive")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        if self.version != SAVEPOINT_MANAGER_VERSION:
            raise ValueError("bad version pin")
        if self.schema != SAVEPOINT_MANAGER_SCHEMA:
            raise ValueError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "savepoint_id": self.savepoint_id,
            "dispose_seq": self.dispose_seq,
            "operator_count": self.operator_count,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SavepointHealth:
    """Result of verify(): liveness + integrity check."""

    savepoint_id: str
    restorable: bool
    reason: str
    version: str = SAVEPOINT_MANAGER_VERSION
    schema: str = SAVEPOINT_MANAGER_SCHEMA

    def __post_init__(self) -> None:
        _check_sp_id(self.savepoint_id)
        if not isinstance(self.restorable, bool):
            raise TypeError("restorable must be bool")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("reason must be a non-empty str")
        if self.version != SAVEPOINT_MANAGER_VERSION:
            raise ValueError("bad version pin")
        if self.schema != SAVEPOINT_MANAGER_SCHEMA:
            raise ValueError("bad schema pin")

    def as_dict(self) -> dict:
        return {
            "savepoint_id": self.savepoint_id,
            "restorable": self.restorable,
            "reason": self.reason,
            "version": self.version,
            "schema": self.schema,
        }


class SavepointManager:
    """Registry owning the savepoint ledger: trigger / restore / dispose."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, "_SavepointRecord"] = {}
        self._disposed: set = set()
        self._next_n = 1
        self._last_trigger_seq = -1

    def trigger(self, operator_states: Mapping[str, bytes], seq: object) -> SavepointHandle:
        """Take a full snapshot of operator state. Returns a pinned handle."""
        seq = _check_seq(seq)
        states = _check_operator_states(operator_states)
        with self._lock:
            if seq < self._last_trigger_seq:
                raise ValueError(
                    f"seq {seq} is older than the last trigger "
                    f"({self._last_trigger_seq}); savepoint ids are append-only"
                )
            savepoint_id = f"savepoint-{self._next_n}"
            self._next_n += 1
            state_pins = tuple((uid, _pin_state(payload)) for uid, payload in states)
            digest = _pin_savepoint(savepoint_id, state_pins, seq)
            self._records[savepoint_id] = _SavepointRecord(
                savepoint_id=savepoint_id,
                created_seq=seq,
                state_pins=state_pins,
                states=states,
                digest=digest,
            )
            self._last_trigger_seq = seq
            return SavepointHandle(
                savepoint_id=savepoint_id,
                created_seq=seq,
                digest=digest,
                operator_uids=tuple(uid for uid, _ in states),
            )

    def _resolve(self, handle_or_id: object) -> str:
        """Normalize a SavepointHandle or raw id to a validated id."""
        if isinstance(handle_or_id, SavepointHandle):
            return handle_or_id.savepoint_id
        return _check_sp_id(handle_or_id)

    def _live_record(self, sp_id: str) -> "_SavepointRecord":
        """Return the record for a restorable savepoint, fail-closed."""
        if sp_id in self._disposed:
            raise DisposedSavepointError(f"savepoint {sp_id!r} is disposed")
        record = self._records.get(sp_id)
        if record is None:
            raise UnknownSavepointError(f"unknown savepoint {sp_id!r}")
        return record

    def restore(
        self,
        handle_or_id: object,
        seq: object,
        job_operator_uids: object = (),
        allow_unmapped_operators: bool = False,
    ) -> RestoredSnapshot:
        """Restore a savepoint into a job's operator set.

        Every savepoint operator must appear in ``job_operator_uids``
        unless ``allow_unmapped_operators`` is true (Flink's
        ``--allowNonRestoredState``). The savepoint digest re-pins before
        any byte is returned.
        """
        seq = _check_seq(seq)
        sp_id = self._resolve(handle_or_id)
        if not isinstance(allow_unmapped_operators, bool):
            raise TypeError("allow_unmapped_operators must be bool")
        if not isinstance(job_operator_uids, (tuple, list)):
            raise TypeError("job_operator_uids must be a tuple/list of str")
        job_uids = tuple(job_operator_uids)
        for uid in job_uids:
            if not isinstance(uid, str) or not uid:
                raise TypeError("job_operator_uids must contain non-empty str")
        with self._lock:
            record = self._live_record(sp_id)
            expected = _pin_savepoint(record.savepoint_id, record.state_pins,
                                      record.created_seq)
            if not hmac.compare_digest(expected, record.digest):
                raise IncompatibleSavepointError(
                    f"savepoint {sp_id!r} failed digest re-pin (corrupted record)"
                )
            saved_uids = {uid for uid, _ in record.states}
            unmapped = saved_uids - set(job_uids)
            if unmapped and not allow_unmapped_operators:
                raise IncompatibleSavepointError(
                    f"savepoint {sp_id!r} operators {sorted(unmapped)} have no "
                    "matching job operator (set allow_unmapped_operators=True "
                    "to drop them)"
                )
            copied = tuple((uid, bytes(payload)) for uid, payload in record.states)
            return RestoredSnapshot(
                savepoint_id=sp_id,
                restore_seq=seq,
                states=copied,
                digest=record.digest,
            )

    def dispose(self, handle_or_id: object, seq: object) -> DisposalRecord:
        """Delete a savepoint's data from the registry. Irreversible here."""
        seq = _check_seq(seq)
        sp_id = self._resolve(handle_or_id)
        with self._lock:
            if sp_id in self._disposed:
                raise DisposedSavepointError(f"savepoint {sp_id!r} is already disposed")
            record = self._records.get(sp_id)
            if record is None:
                raise UnknownSavepointError(f"unknown savepoint {sp_id!r}")
            self._disposed.add(sp_id)
            del self._records[sp_id]
            return DisposalRecord(
                savepoint_id=sp_id,
                dispose_seq=seq,
                operator_count=len(record.states),
                digest=record.digest,
            )

    def verify(self, handle_or_id: object) -> SavepointHealth:
        """Liveness + integrity check. Never raises on an unhealthy savepoint."""
        sp_id = self._resolve(handle_or_id)
        with self._lock:
            if sp_id in self._disposed:
                return SavepointHealth(
                    savepoint_id=sp_id,
                    restorable=False,
                    reason="disposed",
                )
            record = self._records.get(sp_id)
            if record is None:
                raise UnknownSavepointError(f"unknown savepoint {sp_id!r}")
            expected = _pin_savepoint(record.savepoint_id, record.state_pins,
                                      record.created_seq)
            if not hmac.compare_digest(expected, record.digest):
                return SavepointHealth(
                    savepoint_id=sp_id,
                    restorable=False,
                    reason="digest-mismatch",
                )
            return SavepointHealth(
                savepoint_id=sp_id,
                restorable=True,
                reason="healthy",
            )

    def info(self, handle_or_id: object) -> dict:
        """Pinned metadata for a live savepoint (state *pins*, never bytes)."""
        sp_id = self._resolve(handle_or_id)
        with self._lock:
            record = self._live_record(sp_id)
            return {
                "savepoint_id": record.savepoint_id,
                "created_seq": record.created_seq,
                "operator_uids": [uid for uid, _ in record.states],
                "state_pins": [
                    {"operator_uid": uid, "state_pin": pin}
                    for uid, pin in record.state_pins
                ],
                "digest": record.digest,
                "version": SAVEPOINT_MANAGER_VERSION,
                "schema": SAVEPOINT_MANAGER_SCHEMA,
            }

    def list(self) -> Tuple[SavepointHandle, ...]:
        """Live savepoints in creation order."""
        with self._lock:
            handles = []
            for record in self._records.values():
                handles.append(
                    SavepointHandle(
                        savepoint_id=record.savepoint_id,
                        created_seq=record.created_seq,
                        digest=record.digest,
                        operator_uids=tuple(uid for uid, _ in record.states),
                    )
                )
            return tuple(sorted(handles, key=lambda h: h.created_seq))


class _SavepointRecord:
    """Internal registry entry (not a public API)."""

    def __init__(self, savepoint_id: str, created_seq: int,
                 state_pins: Tuple[Tuple[str, str], ...],
                 states: Tuple[Tuple[str, bytes], ...],
                 digest: str) -> None:
        self.savepoint_id = savepoint_id
        self.created_seq = created_seq
        self.state_pins = state_pins
        self.states = states
        self.digest = digest


def savepoint_manager_audit_event(kind: object, seq: object,
                                  savepoint_id: Optional[object] = None) -> dict:
    """Audit-shaped record for a savepoint-manager observation."""
    if kind not in AUDIT_KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    _check_seq(seq)
    if savepoint_id is not None:
        _check_sp_id(savepoint_id)
    body: dict[str, Any] = {
        "event": "savepoint-manager",
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
    }
    if savepoint_id is not None:
        body["savepoint_id"] = savepoint_id
    return body


def main() -> None:
    mgr = SavepointManager()
    handle = mgr.trigger({"op-a": b"\x00\x01state", "op-b": b"\x02state"}, seq=1)
    assert handle.savepoint_id == "savepoint-1", handle
    health = mgr.verify(handle.savepoint_id)
    assert health.restorable, health
    snap = mgr.restore(handle.savepoint_id, seq=2, job_operator_uids=("op-a", "op-b"))
    assert snap.state_for("op-a") == b"\x00\x01state", snap
    assert mgr.info(handle.savepoint_id)["digest"] == handle.digest
    receipt = mgr.dispose(handle.savepoint_id, seq=3)
    assert receipt.operator_count == 2, receipt
    try:
        mgr.restore(handle.savepoint_id, seq=4, job_operator_uids=("op-a", "op-b"))
        raise AssertionError("restoring a disposed savepoint must fail")
    except DisposedSavepointError:
        pass
    print("savepoint-manager OK: trigger, restore, UID check, dispose")


if __name__ == "__main__":
    main()
