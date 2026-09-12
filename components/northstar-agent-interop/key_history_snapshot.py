"""Pinned key-history prefixes and historical as-of verdicts.

A current lifecycle verdict is not enough for signed evidence: a later
revocation must not rewrite what was true at an earlier history revision. This
module verifies an exact prefix of the existing digest-only key history and
derives a key state from that prefix. Revision numbers are ordering metadata,
not trusted wall-clock timestamps.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from key_lifecycle import KeyHistory, KeyLifecycleError, KeyRecord, ZERO, _record_digest

SCHEMA = "northstar.key-history-snapshot.v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIELDS = frozenset({"schema_version", "revision", "anchor_digest", "head_digest"})


class SnapshotError(ValueError):
    """Malformed, stale, or unverifiable historical key snapshot."""


@dataclass(frozen=True)
class KeyHistorySnapshot:
    schema_version: str
    revision: int
    anchor_digest: str
    head_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "revision": self.revision,
            "anchor_digest": self.anchor_digest,
            "head_digest": self.head_digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "KeyHistorySnapshot":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise SnapshotError("snapshot fields are invalid")
        if value["schema_version"] != SCHEMA:
            raise SnapshotError("snapshot schema is invalid")
        revision = value["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise SnapshotError("snapshot revision is invalid")
        for field in ("anchor_digest", "head_digest"):
            if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
                raise SnapshotError(f"snapshot {field} is invalid")
        return cls(SCHEMA, revision, value["anchor_digest"], value["head_digest"])


@dataclass(frozen=True)
class SnapshotVerdict:
    state: str
    reasons: tuple[str, ...] = ()
    revision: int = 0
    head_digest: str = ""


@dataclass(frozen=True)
class HistoricalKeyVerdict:
    state: str
    reasons: tuple[str, ...]
    revision: int
    head_digest: str


def _read_prefix(history: KeyHistory, revision: int) -> tuple[tuple[KeyRecord, ...], str | None]:
    path = history.path
    if not path.exists():
        return (), "history_missing"
    try:
        raw = path.read_bytes()
    except OSError:
        return (), "history_unreadable"
    lines = raw.split(b"\n")
    if not raw.endswith(b"\n"):
        lines = lines[:-1]
    records: list[KeyRecord] = []
    previous = ZERO
    for line in lines:
        if not line.strip():
            continue
        if len(records) >= revision:
            break
        try:
            record = KeyRecord.from_dict(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyLifecycleError):
            return tuple(records), "prefix_corrupt"
        expected_revision = len(records) + 1
        if record.revision != expected_revision:
            return tuple(records), "revision_gap"
        if record.previous_digest != previous:
            return tuple(records), "chain_break"
        expected_digest = _record_digest(
            record.revision, record.key_id, record.material_digest,
            record.action, record.previous_digest,
        )
        if record.record_digest != expected_digest:
            return tuple(records), "record_digest_mismatch"
        records.append(record)
        previous = record.record_digest
    if len(records) < revision:
        return tuple(records), "prefix_missing"
    return tuple(records), None


def make_snapshot(history: KeyHistory, revision: int | None = None) -> KeyHistorySnapshot:
    if not isinstance(history, KeyHistory):
        raise SnapshotError("history is invalid")
    records = history.records
    if not records:
        raise SnapshotError("history is empty")
    selected = len(records) if revision is None else revision
    if not isinstance(selected, int) or isinstance(selected, bool) or selected < 1 or selected > len(records):
        raise SnapshotError("snapshot revision is outside history")
    return KeyHistorySnapshot(
        SCHEMA,
        selected,
        records[0].record_digest,
        records[selected - 1].record_digest,
    )


def verify_snapshot(history: KeyHistory, snapshot: KeyHistorySnapshot) -> SnapshotVerdict:
    if not isinstance(history, KeyHistory):
        raise SnapshotError("history is invalid")
    try:
        snapshot = KeyHistorySnapshot.from_dict(snapshot.to_dict())
    except AttributeError as exc:
        raise SnapshotError("snapshot is invalid") from exc
    records, error = _read_prefix(history, snapshot.revision)
    if error is not None:
        return SnapshotVerdict("unverifiable", (error,), snapshot.revision, snapshot.head_digest)
    if records[0].record_digest != snapshot.anchor_digest:
        return SnapshotVerdict("unverifiable", ("snapshot_anchor_mismatch",), snapshot.revision, snapshot.head_digest)
    if history.anchor is not None and history.anchor != snapshot.anchor_digest:
        return SnapshotVerdict("untrusted-anchor", ("anchor_mismatch",), snapshot.revision, snapshot.head_digest)
    if history.anchor is not None and history.anchor != records[0].record_digest:
        return SnapshotVerdict("untrusted-anchor", ("anchor_mismatch",), snapshot.revision, snapshot.head_digest)
    if records[-1].record_digest != snapshot.head_digest:
        return SnapshotVerdict("unverifiable", ("head_mismatch",), snapshot.revision, snapshot.head_digest)
    if history.anchor is None:
        return SnapshotVerdict("verified-unpinned", ("anchor_unpinned",), snapshot.revision, snapshot.head_digest)
    return SnapshotVerdict("trusted", (), snapshot.revision, snapshot.head_digest)


def _derive(records: tuple[KeyRecord, ...], key_id: str) -> str:
    matching = [record for record in records if record.key_id == key_id]
    if not matching:
        return "unknown-key"
    last = matching[-1]
    if last.action == "revoked":
        return "revoked"
    if last.action == "rotated":
        return "trusted"
    retired = any(record.revision > last.revision and record.action == "rotated" for record in records)
    return "trusted-retired" if retired else "trusted"


def verdict_at(history: KeyHistory, key_id: str, snapshot: KeyHistorySnapshot) -> HistoricalKeyVerdict:
    if not isinstance(key_id, str) or not key_id:
        raise SnapshotError("key_id is invalid")
    verdict = verify_snapshot(history, snapshot)
    if verdict.state not in {"trusted", "verified-unpinned"}:
        return HistoricalKeyVerdict("unverifiable", verdict.reasons, verdict.revision, verdict.head_digest)
    records, error = _read_prefix(history, verdict.revision)
    if error is not None:
        return HistoricalKeyVerdict("unverifiable", (error,), verdict.revision, verdict.head_digest)
    state = _derive(records, key_id)
    if state == "unknown-key":
        reasons = ("key_not_in_snapshot",) + verdict.reasons
    else:
        reasons = verdict.reasons
    return HistoricalKeyVerdict(state, reasons, verdict.revision, verdict.head_digest)


__all__ = [
    "SCHEMA", "SnapshotError", "KeyHistorySnapshot", "SnapshotVerdict",
    "HistoricalKeyVerdict", "make_snapshot", "verify_snapshot", "verdict_at",
]
