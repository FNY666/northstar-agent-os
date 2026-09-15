"""Append-only preservation of contradictory admission witnesses.

The ledger records that two valid admission witnesses for one claim disagree.
Its canonical witness order exists only for idempotency; it never marks a winner.
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

from admission_witness import AdmissionWitness, WitnessError

SCHEMA = "northstar.evidence-conflict-ledger.v1"
META_SCHEMA = "northstar.evidence-conflict-ledger-meta.v1"
ZERO = "sha256:" + "0" * 64
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECORD_FIELDS = frozenset({
    "schema_version", "sequence", "conflict_id", "claim_digest",
    "witness_a_digest", "witness_b_digest", "evidence_root_a", "evidence_root_b",
    "claimed_state_a", "claimed_state_b", "reasons", "previous_digest",
    "record_digest",
})


class ConflictLedgerError(ValueError):
    """Malformed, non-conflicting, stale, or unverifiable conflict ledger state."""


@dataclass(frozen=True)
class ConflictObservation:
    schema_version: str
    sequence: int
    conflict_id: str
    claim_digest: str
    witness_a_digest: str
    witness_b_digest: str
    evidence_root_a: str
    evidence_root_b: str
    claimed_state_a: str
    claimed_state_b: str
    reasons: tuple[str, ...]
    previous_digest: str
    record_digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "conflict_id": self.conflict_id,
            "claim_digest": self.claim_digest,
            "witness_a_digest": self.witness_a_digest,
            "witness_b_digest": self.witness_b_digest,
            "evidence_root_a": self.evidence_root_a,
            "evidence_root_b": self.evidence_root_b,
            "claimed_state_a": self.claimed_state_a,
            "claimed_state_b": self.claimed_state_b,
            "reasons": list(self.reasons),
            "previous_digest": self.previous_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "record_digest": self.record_digest}

    @classmethod
    def from_dict(cls, value: Any) -> "ConflictObservation":
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise ConflictLedgerError("conflict record fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise ConflictLedgerError("conflict record schema is invalid")
        sequence = value["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise ConflictLedgerError("conflict record sequence is invalid")
        for field in (
            "conflict_id", "claim_digest", "witness_a_digest", "witness_b_digest",
            "evidence_root_a", "evidence_root_b", "previous_digest", "record_digest",
        ):
            _digest(value[field], field)
        if value["witness_a_digest"] >= value["witness_b_digest"]:
            raise ConflictLedgerError("conflict witness order is not canonical")
        for field in ("claimed_state_a", "claimed_state_b"):
            if value[field] not in {"verified", "verified-unpinned"}:
                raise ConflictLedgerError("conflict claimed state is invalid")
        reasons = _reasons(value["reasons"])
        record = cls(
            SCHEMA, sequence, value["conflict_id"], value["claim_digest"],
            value["witness_a_digest"], value["witness_b_digest"],
            value["evidence_root_a"], value["evidence_root_b"],
            value["claimed_state_a"], value["claimed_state_b"], reasons,
            value["previous_digest"], value["record_digest"],
        )
        if record.computed_conflict_id != record.conflict_id:
            raise ConflictLedgerError("conflict identifier mismatch")
        if record.computed_digest != record.record_digest:
            raise ConflictLedgerError("conflict record digest mismatch")
        return record

    @property
    def computed_conflict_id(self) -> str:
        return _hash(
            b"northstar.evidence-conflict-id.v1\0",
            {
                "claim_digest": self.claim_digest,
                "witness_a_digest": self.witness_a_digest,
                "witness_b_digest": self.witness_b_digest,
                "reasons": list(self.reasons),
            },
        )

    @property
    def computed_digest(self) -> str:
        return _hash(b"northstar.evidence-conflict-record.v1\0", self.payload())


@dataclass(frozen=True)
class ConflictLedgerVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    record_count: int = 0
    head_digest: str = ""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ConflictLedgerError("conflict value is not canonical JSON") from exc


def _hash(prefix: bytes, value: Any) -> str:
    return "sha256:" + hashlib.sha256(prefix + _canonical(value)).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ConflictLedgerError(f"{field} is invalid")
    return value


def _reasons(value: Any) -> tuple[str, ...]:
    if (not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item for item in value)
            or len(set(value)) != len(value)
            or list(value) != sorted(value)):
        raise ConflictLedgerError("conflict reasons are invalid")
    return tuple(value)


def _validated_witness(value: Any) -> AdmissionWitness:
    try:
        return AdmissionWitness.from_dict(value.to_dict())
    except (AttributeError, WitnessError) as exc:
        raise ConflictLedgerError("admission witness is invalid") from exc


def _conflict(left: AdmissionWitness, right: AdmissionWitness) -> tuple[AdmissionWitness, AdmissionWitness, tuple[str, ...]]:
    left = _validated_witness(left)
    right = _validated_witness(right)
    if left.claim_digest != right.claim_digest:
        raise ConflictLedgerError("different claims are not conflicts")
    if left.witness_digest == right.witness_digest:
        raise ConflictLedgerError("identical witnesses are not conflicts")
    first, second = sorted((left, right), key=lambda item: item.witness_digest)
    reasons: list[str] = []
    if first.evidence_root != second.evidence_root:
        reasons.append("evidence_root_mismatch")
    if first.claimed_evidence_state != second.claimed_evidence_state:
        reasons.append("claimed_evidence_state_mismatch")
    if not reasons:
        raise ConflictLedgerError("same evidence is not a conflict")
    return first, second, tuple(sorted(reasons))


class EvidenceConflictLedger:
    """Same-host durable conflict observations without resolution semantics."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "conflicts.jsonl"
        self.lock_path = self.root / "conflicts.lock"
        self.meta_path = self.root / "conflicts.meta"
        self._ensure_meta()

    def _ensure_meta(self) -> None:
        if self.meta_path.exists():
            try:
                value = json.loads(self.meta_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ConflictLedgerError("conflict metadata is corrupt") from exc
            if (not isinstance(value, dict)
                    or value.get("schema_version") != META_SCHEMA
                    or not isinstance(value.get("history_started"), bool)):
                raise ConflictLedgerError("conflict metadata is invalid")
            return
        self._write_meta({"schema_version": META_SCHEMA, "history_started": False})

    def _write_meta(self, value: dict[str, Any]) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".conflicts.meta.", dir=self.root, text=True,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.meta_path)
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _history_started(self) -> bool:
        try:
            return bool(json.loads(self.meta_path.read_text(encoding="utf-8")).get("history_started"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConflictLedgerError("conflict metadata is corrupt") from exc

    @contextmanager
    def _lock(self):
        with self.lock_path.open("a+") as handle:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read_records(self) -> tuple[list[ConflictObservation], str | None]:
        if not self.path.exists():
            return ([], "history_missing") if self._history_started() else ([], None)
        try:
            raw = self.path.read_bytes()
        except OSError:
            return [], "history_unreadable"
        lines = raw.split(b"\n")
        if not raw.endswith(b"\n"):
            lines = lines[:-1]
        records: list[ConflictObservation] = []
        previous = ZERO
        expected_sequence = 1
        for line in lines:
            if not line.strip():
                continue
            try:
                record = ConflictObservation.from_dict(json.loads(line.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError, ConflictLedgerError):
                return records, "history_corrupt"
            if record.sequence != expected_sequence or record.previous_digest != previous:
                return records, "chain_break"
            records.append(record)
            previous = record.record_digest
            expected_sequence += 1
        return records, None

    @property
    def records(self) -> list[ConflictObservation]:
        records, error = self._read_records()
        if error is not None:
            raise ConflictLedgerError(error)
        return records

    def verify(self) -> ConflictLedgerVerdict:
        records, error = self._read_records()
        if error is not None:
            return ConflictLedgerVerdict("unverifiable", (error,), len(records),
                                         records[-1].record_digest if records else "")
        return ConflictLedgerVerdict(
            "replayable", (), len(records), records[-1].record_digest if records else ZERO,
        )

    def _append(self, records: list[ConflictObservation], first: AdmissionWitness,
                second: AdmissionWitness, reasons: tuple[str, ...]) -> ConflictObservation:
        sequence = len(records) + 1
        previous = records[-1].record_digest if records else ZERO
        seed = ConflictObservation(
            SCHEMA, sequence, "", first.claim_digest, first.witness_digest,
            second.witness_digest, first.evidence_root, second.evidence_root,
            first.claimed_evidence_state, second.claimed_evidence_state, reasons,
            previous, "",
        )
        conflict_id = seed.computed_conflict_id
        unsigned = ConflictObservation(
            SCHEMA, sequence, conflict_id, first.claim_digest, first.witness_digest,
            second.witness_digest, first.evidence_root, second.evidence_root,
            first.claimed_evidence_state, second.claimed_evidence_state, reasons,
            previous, "",
        )
        record = ConflictObservation(
            unsigned.schema_version, unsigned.sequence, unsigned.conflict_id,
            unsigned.claim_digest, unsigned.witness_a_digest, unsigned.witness_b_digest,
            unsigned.evidence_root_a, unsigned.evidence_root_b,
            unsigned.claimed_state_a, unsigned.claimed_state_b, unsigned.reasons,
            unsigned.previous_digest, unsigned.computed_digest,
        )
        if not self._history_started():
            self._write_meta({"schema_version": META_SCHEMA, "history_started": True})
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        return record

    def record_conflict(self, left: AdmissionWitness, right: AdmissionWitness) -> ConflictObservation:
        first, second, reasons = _conflict(left, right)
        with self._lock():
            records, error = self._read_records()
            if error is not None:
                raise ConflictLedgerError(error)
            seed = ConflictObservation(
                SCHEMA, 1, "", first.claim_digest, first.witness_digest,
                second.witness_digest, first.evidence_root, second.evidence_root,
                first.claimed_evidence_state, second.claimed_evidence_state, reasons,
                ZERO, "",
            )
            conflict_id = seed.computed_conflict_id
            for record in records:
                if record.conflict_id == conflict_id:
                    return record
            return self._append(records, first, second, reasons)


__all__ = [
    "SCHEMA", "ConflictLedgerError", "ConflictObservation", "ConflictLedgerVerdict",
    "EvidenceConflictLedger",
]
