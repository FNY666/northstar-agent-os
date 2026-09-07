"""Version-aware replay and recovery layer for RouteDecision Journal."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

class ReplayVerdict(str, Enum):
    REPLAYABLE = "replayable"
    STALE = "stale"
    CONFLICTING = "conflicting"
    UNVERIFIABLE = "unverifiable"

@dataclass(frozen=True)
class ReplayLineage:
    parent_id: str | None
    attempt: int
    receipt_id: str
    cause: str

    def __post_init__(self) -> None:
        if self.parent_id is not None and not _ID.fullmatch(self.parent_id):
            raise ValueError("parent_id is invalid")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("attempt must be positive")
        if not isinstance(self.receipt_id, str) or not _ID.fullmatch(self.receipt_id):
            raise ValueError("receipt_id is invalid")
        if not isinstance(self.cause, str) or not self.cause or len(self.cause) > 128:
            raise ValueError("cause is invalid")

@dataclass(frozen=True)
class ReplayResult:
    verdict: ReplayVerdict
    record: dict[str, Any]
    lineage: ReplayLineage
    reason: str

class MigrationError(ValueError):
    pass

class MigrationRegistry:
    def __init__(self) -> None:
        self._transforms: dict[tuple[str, str], Callable[[dict[str, Any]], dict[str, Any]]] = {}

    def register(self, source_version: str, target_version: str,
                 transform: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        if not _ID.fullmatch(source_version) or not _ID.fullmatch(target_version) or source_version == target_version:
            raise MigrationError("migration versions are invalid")
        if not callable(transform) or (source_version, target_version) in self._transforms:
            raise MigrationError("migration registration is invalid")
        self._transforms[(source_version, target_version)] = transform

    def migrate(self, raw_record: dict[str, Any], *, target_version: str) -> tuple[dict[str, Any], tuple[str, ...]]:
        if not isinstance(raw_record, dict):
            raise MigrationError("raw record must be an object")
        current = raw_record.get("schema_version")
        if not isinstance(current, str):
            raise MigrationError("source schema version is missing")
        if current == target_version:
            return dict(raw_record), ()
        chain: list[str] = []
        visited: set[str] = set()
        value = dict(raw_record)
        while current != target_version:
            if current in visited:
                raise MigrationError("migration cycle detected")
            visited.add(current)
            candidates = [(dst, fn) for (src, dst), fn in self._transforms.items() if src == current]
            if len(candidates) != 1:
                raise MigrationError("migration path is unknown or ambiguous")
            next_version, transform = candidates[0]
            try:
                migrated = transform(dict(value))
            except Exception as exc:
                raise MigrationError("migration transform failed") from exc
            if not isinstance(migrated, dict) or migrated.get("schema_version") != next_version:
                raise MigrationError("migration dropped or changed schema identity")
            if ("idempotency_key" in value and migrated.get("idempotency_key") != value["idempotency_key"]):
                raise MigrationError("migration dropped or changed idempotency identity")
            if ("request_digest" in value and migrated.get("request_digest") != value["request_digest"]):
                raise MigrationError("migration dropped or changed request identity")
            value = migrated
            chain.append(f"{current}->{next_version}")
            current = next_version
        return value, tuple(chain)

def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()

def _safe_record(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    if "prompt" in record or "raw_output" in record or "secret" in record or "context" in record:
        return False
    return True

def classify_replay(record: dict[str, Any], current_snapshot: list[dict[str, Any]],
                    current_policy_revision: str, *, request_digest: str,
                    lineage: ReplayLineage) -> ReplayResult:
    if not _safe_record(record) or not isinstance(current_snapshot, list):
        return ReplayResult(ReplayVerdict.UNVERIFIABLE, dict(record) if isinstance(record, dict) else {}, lineage, "record evidence is incomplete")
    if record.get("request_digest") != request_digest:
        return ReplayResult(ReplayVerdict.CONFLICTING, dict(record), lineage, "request digest changed")
    if record.get("policy_revision") != current_policy_revision:
        return ReplayResult(ReplayVerdict.STALE, dict(record), lineage, "policy revision changed")
    stored = record.get("candidate_snapshot")
    if not isinstance(stored, list) or not stored:
        return ReplayResult(ReplayVerdict.UNVERIFIABLE, dict(record), lineage, "candidate evidence is missing")
    if stored != current_snapshot:
        return ReplayResult(ReplayVerdict.STALE, dict(record), lineage, "candidate snapshot changed")
    if record.get("status") not in {"selected", "failed"}:
        return ReplayResult(ReplayVerdict.UNVERIFIABLE, dict(record), lineage, "decision status is invalid")
    return ReplayResult(ReplayVerdict.REPLAYABLE, dict(record), lineage, "canonical evidence matches")

@dataclass(frozen=True)
class RecoveryCursor:
    sequence: int
    file_offset: int
    last_idempotency_key: str | None
    digest: str

def recover_cursor(path: str | Path) -> RecoveryCursor:
    path = Path(path)
    if not path.exists():
        return RecoveryCursor(0, 0, None, _digest([]))
    sequence = 0
    last_key: str | None = None
    records: list[dict[str, Any]] = []
    offset = 0
    with path.open("rb") as handle:
        for raw in handle:
            next_offset = offset + len(raw)
            if not raw.endswith(b"\n"):
                break
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MigrationError("complete journal line is corrupt") from exc
            if not isinstance(value, dict):
                raise MigrationError("journal line is not an object")
            records.append(value)
            sequence += 1
            last_key = value.get("idempotency_key") if isinstance(value.get("idempotency_key"), str) else None
            offset = next_offset
    return RecoveryCursor(sequence, offset, last_key, _digest(records))

def lineage_for_retry(parent_record: dict[str, Any], *, retry_idempotency_key: str,
                      receipt_id: str) -> ReplayLineage:
    parent = parent_record.get("idempotency_key") if isinstance(parent_record, dict) else None
    if not isinstance(parent, str) or not _ID.fullmatch(parent):
        raise ValueError("parent record has no valid idempotency key")
    return ReplayLineage(parent, int(parent_record.get("attempt", 1)) + 1, receipt_id, "retry")

__all__ = ["MigrationError", "MigrationRegistry", "ReplayLineage", "ReplayResult", "ReplayVerdict", "RecoveryCursor", "classify_replay", "lineage_for_retry", "recover_cursor"]
