"""Durable, non-authorizing anchor for preflight digests.

The preflight artifact can report ``preflight-unpinned`` when a caller has no
retained external digest to compare against. This module retains those digests
so a later run on the same host can compare against a real previous observation
instead of re-verifying the evidence against itself.

A stored pin is a retained observation, never permission: every resolution and
verdict reports ``execution_authorized=False``. The first pin for a plan is
trust-on-first-use and is labelled ``first-use``.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidence_readiness_preflight import EvidenceReadinessPreflight, PreflightError
from readiness_lease_witness import LeaseRegistryWitness, RegistryWitnessError

STORE_SCHEMA = "northstar.evidence-preflight-pins.v1"
RECORD_SCHEMA = "northstar.evidence-preflight-pin-record.v2"
ORIGINS = ("first-use", "verified")
PINNABLE_STATES = ("preflight-ready", "preflight-unpinned")

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_RECORD_FIELDS = frozenset({
    "schema_version", "sequence", "plan_id", "origin", "lease_digest",
    "registry_witness_digest", "decision_digest", "manifest_digest",
    "gate_digest", "recorded_at", "registry_witness", "prev_digest",
    "record_digest",
})
_DIGEST_FIELDS = (
    "lease_digest", "registry_witness_digest", "decision_digest",
    "manifest_digest", "gate_digest",
)


class PinStoreError(ValueError):
    """Raised when pins cannot be recorded or read safely."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PinStoreError("pin record is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PinStoreError(f"{field} must be a sha256 digest")
    return value


def _plan_id(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or _CONTROL.search(value):
        raise PinStoreError("plan_id invalid")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PinStoreError(f"{field} must be an integer")
    return value


def _origin(value: Any) -> str:
    if value not in ORIGINS:
        raise PinStoreError("origin invalid")
    return value


def _witness_payload(value: Any, expected_digest: str) -> dict | None:
    """Return the canonical witness payload, or None when absent."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PinStoreError("registry_witness must be an object or null")
    try:
        witness = LeaseRegistryWitness.from_dict(value)
    except RegistryWitnessError as exc:
        raise PinStoreError("registry_witness invalid") from exc
    if witness.witness_digest != expected_digest:
        raise PinStoreError("registry_witness does not match its digest")
    return witness.to_dict()


@dataclass(frozen=True)
class PreflightPinRecord:
    schema_version: str
    sequence: int
    plan_id: str
    origin: str
    lease_digest: str
    registry_witness_digest: str
    decision_digest: str
    manifest_digest: str
    gate_digest: str
    recorded_at: int
    registry_witness: dict | None
    prev_digest: str | None
    record_digest: str

    def unsigned_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "plan_id": self.plan_id,
            "origin": self.origin,
            "lease_digest": self.lease_digest,
            "registry_witness_digest": self.registry_witness_digest,
            "decision_digest": self.decision_digest,
            "manifest_digest": self.manifest_digest,
            "gate_digest": self.gate_digest,
            "recorded_at": self.recorded_at,
            "registry_witness": self.registry_witness,
            "prev_digest": self.prev_digest,
        }

    def to_dict(self) -> dict:
        return {**self.unsigned_dict(), "record_digest": self.record_digest}

    @property
    def computed_digest(self) -> str:
        return _hash(RECORD_SCHEMA.encode() + b"\0", self.unsigned_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "PreflightPinRecord":
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise PinStoreError("pin record fields invalid")
        if value["schema_version"] != RECORD_SCHEMA:
            raise PinStoreError("pin record schema invalid")
        sequence = _integer(value["sequence"], "sequence")
        if sequence < 1:
            raise PinStoreError("sequence must be positive")
        recorded_at = _integer(value["recorded_at"], "recorded_at")
        digests = {field: _digest(value[field], field) for field in _DIGEST_FIELDS}
        record_digest = _digest(value["record_digest"], "record_digest")
        prev = value["prev_digest"]
        if prev is not None:
            prev = _digest(prev, "prev_digest")
        record = cls(
            RECORD_SCHEMA, sequence, _plan_id(value["plan_id"]), _origin(value["origin"]),
            digests["lease_digest"], digests["registry_witness_digest"],
            digests["decision_digest"], digests["manifest_digest"], digests["gate_digest"],
            recorded_at,
            _witness_payload(value["registry_witness"], digests["registry_witness_digest"]),
            prev, record_digest,
        )
        if record.computed_digest != record_digest:
            raise PinStoreError("pin record digest mismatch")
        return record


@dataclass(frozen=True)
class PinResolution:
    state: str
    plan_id: str = ""
    lease_digest: str = ""
    registry_witness_digest: str = ""
    decision_digest: str = ""
    manifest_digest: str = ""
    gate_digest: str = ""
    origin: str = ""
    registry_witness: dict | None = None
    witness_replayable: bool = False
    pin_record_digest: str = ""
    plan_sequence: int = 0
    chain_sequence: int = 0
    chain_head_digest: str = ""
    reasons: tuple[str, ...] = ()
    execution_authorized: bool = False


@dataclass(frozen=True)
class PinVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    execution_authorized: bool = False


class PreflightPinStore:
    """Same-host pin history with flock, fsync, and a hash-chained log."""

    def __init__(self, path: str | os.PathLike) -> None:
        self._root = Path(path)
        self._log = self._root / "pins.jsonl"
        self._meta = self._root / "pins.meta.json"
        self._lock = self._root / "pins.lock"

    @property
    def path(self) -> Path:
        return self._root

    @contextmanager
    def _locked(self):
        self._root.mkdir(parents=True, exist_ok=True)
        with self._lock.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _write_meta(self) -> None:
        if self._meta.exists():
            return
        payload = {"schema_version": STORE_SCHEMA}
        fd, temp = tempfile.mkstemp(dir=str(self._root), prefix=".pins-meta-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self._meta)
        except BaseException:
            if os.path.exists(temp):
                os.unlink(temp)
            raise
        directory = os.open(str(self._root), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_records(self) -> tuple[list[PreflightPinRecord], str | None]:
        if not self._log.exists():
            if self._meta.exists():
                return [], "pin history missing"
            return [], None
        records: list[PreflightPinRecord] = []
        previous: str | None = None
        try:
            with self._log.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.endswith("\n") or not line.strip():
                        return [], "pin history malformed"
                    try:
                        record = PreflightPinRecord.from_dict(json.loads(line))
                    except (json.JSONDecodeError, PinStoreError):
                        return [], "pin history malformed"
                    if record.sequence != len(records) + 1:
                        return [], "pin history reordered"
                    if record.prev_digest != previous:
                        return [], "pin history chain broken"
                    previous = record.record_digest
                    records.append(record)
        except OSError:
            return [], "pin history unreadable"
        return records, None

    def _append(self, records: list[PreflightPinRecord], record: PreflightPinRecord) -> None:
        line = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._log.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(str(self._root), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def pin_preflight(
        self, plan_id: str, preflight: Any, *, now: int, witness: Any = None
    ) -> PreflightPinRecord:
        plan = _plan_id(plan_id)
        if not isinstance(preflight, EvidenceReadinessPreflight):
            raise PinStoreError("preflight invalid")
        if preflight.state not in PINNABLE_STATES:
            raise PinStoreError("preflight is not current")
        try:
            normalized = EvidenceReadinessPreflight.from_dict(preflight.to_dict())
        except PreflightError as exc:
            raise PinStoreError("preflight invalid") from exc
        payload = None
        if witness is not None:
            if not isinstance(witness, LeaseRegistryWitness):
                raise PinStoreError("registry witness invalid")
            if witness.witness_digest != normalized.registry_witness_digest:
                raise PinStoreError("registry witness does not match preflight")
            payload = witness.to_dict()
        timestamp = _integer(now, "now")
        origin = "verified" if normalized.state == "preflight-ready" else "first-use"
        with self._locked():
            records, error = self._read_records()
            if error is not None:
                raise PinStoreError(error)
            existing = [record for record in records if record.plan_id == plan]
            if existing:
                latest = existing[-1]
                if (
                    latest.origin == origin
                    and latest.registry_witness == payload
                    and all(
                        getattr(latest, field) == getattr(normalized, field)
                        for field in _DIGEST_FIELDS
                    )
                ):
                    return latest
            record = PreflightPinRecord(
                RECORD_SCHEMA,
                len(records) + 1,
                plan,
                origin,
                normalized.lease_digest,
                normalized.registry_witness_digest,
                normalized.decision_digest,
                normalized.manifest_digest,
                normalized.gate_digest,
                timestamp,
                payload,
                records[-1].record_digest if records else None,
                "",
            )
            record = PreflightPinRecord(
                **{**record.unsigned_dict(), "record_digest": record.computed_digest}
            )
            self._write_meta()
            self._append(records, record)
            return record

    def resolve(self, plan_id: str) -> PinResolution:
        plan = _plan_id(plan_id)
        with self._locked():
            records, error = self._read_records()
            if error is not None:
                return PinResolution("pins-unverifiable", plan_id=plan, reasons=(error,))
            if not records:
                return PinResolution("pins-unrecorded", plan_id=plan)
            matching = [record for record in records if record.plan_id == plan]
            if not matching:
                return PinResolution(
                    "pins-unrecorded", plan_id=plan, chain_sequence=len(records),
                    chain_head_digest=records[-1].record_digest,
                )
            latest = matching[-1]
            return PinResolution(
                "pins-current",
                plan_id=plan,
                lease_digest=latest.lease_digest,
                registry_witness_digest=latest.registry_witness_digest,
                decision_digest=latest.decision_digest,
                manifest_digest=latest.manifest_digest,
                gate_digest=latest.gate_digest,
                origin=latest.origin,
                registry_witness=latest.registry_witness,
                witness_replayable=latest.registry_witness is not None,
                pin_record_digest=latest.record_digest,
                plan_sequence=len(matching),
                chain_sequence=len(records),
                chain_head_digest=records[-1].record_digest,
                reasons=(
                    (
                        "trust-on-first-use"
                        if latest.origin == "first-use"
                        else "externally-pinned"
                    ),
                )
                + (() if latest.registry_witness is not None else ("witness_payload_absent",)),
            )

    def chain_head(self) -> tuple[int, str] | None:
        with self._locked():
            records, error = self._read_records()
            if error is not None or not records:
                return None
            return len(records), records[-1].record_digest


def restore_witness(resolution: Any) -> LeaseRegistryWitness:
    """Rebuild the pinned observation so a later run can re-verify it.

    A witness digest binds its injected observation time, so a restarted process
    cannot rebuild a matching witness by re-observing. The payload stored with
    the pin is the only honest source for that past observation.
    """
    if not isinstance(resolution, PinResolution):
        raise PinStoreError("resolution invalid")
    if resolution.state != "pins-current":
        raise PinStoreError("resolution is not current")
    if resolution.registry_witness is None:
        raise PinStoreError("resolution has no replayable witness")
    try:
        return LeaseRegistryWitness.from_dict(resolution.registry_witness)
    except RegistryWitnessError as exc:
        raise PinStoreError("stored registry witness invalid") from exc


def verify_pin_resolution(
    resolution: Any,
    store: Any,
    *,
    expected_chain_head_digest: str | None,
    expected_chain_sequence: int | None,
) -> PinVerdict:
    if not isinstance(resolution, PinResolution):
        raise PinStoreError("resolution invalid")
    if not isinstance(store, PreflightPinStore):
        raise PinStoreError("store invalid")
    if resolution.state != "pins-current":
        return PinVerdict(resolution.state, ("resolution_not_current",))
    if expected_chain_head_digest is None or expected_chain_sequence is None:
        return PinVerdict("pins-unverifiable", ("expected_head_unpinned",))
    _digest(expected_chain_head_digest, "expected_chain_head_digest")
    _integer(expected_chain_sequence, "expected_chain_sequence")
    head = store.chain_head()
    if head is None:
        return PinVerdict("pins-unverifiable", ("pin_history_unverifiable",))
    sequence, digest = head
    if sequence != expected_chain_sequence or digest != expected_chain_head_digest:
        return PinVerdict("pins-stale", ("pin_chain_changed",))
    if (resolution.chain_sequence, resolution.chain_head_digest) != (sequence, digest):
        return PinVerdict("pins-stale", ("resolution_head_changed",))
    return PinVerdict("pins-current")


__all__ = [
    "STORE_SCHEMA", "RECORD_SCHEMA", "PinStoreError", "PreflightPinRecord",
    "PinResolution", "PinVerdict", "PreflightPinStore", "restore_witness",
    "verify_pin_resolution",
]
