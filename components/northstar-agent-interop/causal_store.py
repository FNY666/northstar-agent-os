"""Persistent, tamper-evident storage for typed causal edges."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from route_causality import CausalEdge

_SCHEMA = "northstar.causal-evidence.v2"
_PREFIX = "sha256:"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return _PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _digest_field(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_PREFIX) or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ValueError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be positive integer")
    return value


@dataclass(frozen=True)
class EvidenceCursor:
    sequence: int
    record_digest: str

    def __post_init__(self) -> None:
        _positive(self.sequence, "sequence")
        _digest_field(self.record_digest, "record_digest")


@dataclass(frozen=True)
class CausalEvidenceRecord:
    schema_version: str
    sequence: int
    prev_record_digest: str | None
    record_digest: str
    edge: CausalEdge

    @classmethod
    def create(cls, edge: CausalEdge, *, sequence: int, prev_record_digest: str | None) -> "CausalEvidenceRecord":
        if not isinstance(edge, CausalEdge):
            raise ValueError("edge is invalid")
        try:
            edge = CausalEdge.from_dict(edge.to_dict())
        except (TypeError, ValueError) as error:
            raise ValueError("edge is forged or invalid") from error
        sequence = _positive(sequence, "sequence")
        if sequence == 1:
            if prev_record_digest is not None:
                raise ValueError("first evidence record cannot have predecessor")
        else:
            _digest_field(prev_record_digest, "prev_record_digest")
        unsigned = {
            "schema_version": _SCHEMA,
            "sequence": sequence,
            "prev_record_digest": prev_record_digest,
            "edge": edge.to_dict(),
        }
        return cls(_SCHEMA, sequence, prev_record_digest, _digest(unsigned), edge)

    @classmethod
    def from_dict(cls, value: Any) -> "CausalEvidenceRecord":
        fields = {"schema_version", "sequence", "prev_record_digest", "record_digest", "edge"}
        if not isinstance(value, dict) or set(value) != fields or value["schema_version"] != _SCHEMA:
            raise ValueError("causal evidence record is invalid")
        edge = CausalEdge.from_dict(value["edge"])
        sequence = _positive(value["sequence"], "sequence")
        previous = value["prev_record_digest"]
        if sequence == 1:
            if previous is not None:
                raise ValueError("first evidence record cannot have predecessor")
        else:
            _digest_field(previous, "prev_record_digest")
        supplied = _digest_field(value["record_digest"], "record_digest")
        expected = _digest({
            "schema_version": _SCHEMA,
            "sequence": sequence,
            "prev_record_digest": previous,
            "edge": edge.to_dict(),
        })
        if supplied != expected:
            raise ValueError("causal evidence record digest does not match")
        return cls(_SCHEMA, sequence, previous, supplied, edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "prev_record_digest": self.prev_record_digest,
            "record_digest": self.record_digest,
            "edge": self.edge.to_dict(),
        }


@dataclass(frozen=True)
class EvidenceRecovery:
    verdict: str
    records: tuple[CausalEvidenceRecord, ...]
    cursor: EvidenceCursor | None


class CausalEvidenceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.lock_path, 0o600)

    @contextmanager
    def _locked(self):
        try:
            with self.lock_path.open("a+b") as lock:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                yield
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError as error:
            raise ValueError("causal evidence lock is unavailable") from error

    def _read_locked(self) -> list[CausalEvidenceRecord]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_bytes()
        except OSError as error:
            raise ValueError("causal evidence cannot be read") from error
        records: list[CausalEvidenceRecord] = []
        for raw_line in raw.splitlines(keepends=True):
            if not raw_line.endswith((b"\n", b"\r")):
                raise ValueError("causal evidence contains incomplete record")
            try:
                records.append(CausalEvidenceRecord.from_dict(json.loads(raw_line.decode("utf-8"))))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
                raise ValueError("causal evidence contains invalid record") from error
        previous: CausalEvidenceRecord | None = None
        seen_edges: set[str] = set()
        for expected, record in enumerate(records, start=1):
            if record.edge.edge_digest in seen_edges:
                raise ValueError("causal evidence contains duplicate edge")
            seen_edges.add(record.edge.edge_digest)
            if record.sequence != expected or record.prev_record_digest != (previous.record_digest if previous else None):
                raise ValueError("causal evidence chain is invalid")
            previous = record
        return records

    def append(self, edge: CausalEdge) -> CausalEvidenceRecord:
        if not isinstance(edge, CausalEdge):
            raise ValueError("edge is invalid")
        with self._locked():
            records = self._read_locked()
            for existing in records:
                if existing.edge.to_dict() == edge.to_dict():
                    return existing
            record = CausalEvidenceRecord.create(
                edge,
                sequence=len(records) + 1,
                prev_record_digest=records[-1].record_digest if records else None,
            )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.path.open("ab") as stream:
                    stream.write(_canonical(record.to_dict()) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as error:
                raise ValueError("causal evidence append failed") from error
            return record

    def recover(self, *, expected_cursor: EvidenceCursor | None = None) -> EvidenceRecovery:
        with self._locked():
            records = self._read_locked()
        cursor = None if not records else EvidenceCursor(records[-1].sequence, records[-1].record_digest)
        if expected_cursor is not None and expected_cursor != cursor:
            raise ValueError("causal evidence cursor does not match history")
        return EvidenceRecovery("verified", tuple(records), cursor)
