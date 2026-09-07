"""Versioned receipts for local durable-run control operations.

A control receipt is a projection of an already durable EventStore transition.
It gives an operator or a higher-level API a causal summary without becoming a
second state machine: the event stream remains authoritative, while this
receipt binds actor, command, before/after sequence and the exact event IDs that
were observed.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping

CONTROL_RECEIPT_SCHEMA_VERSION = "northstar.durable-control-receipt.v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[^\s/\\]{1,128}$")
_OPERATIONS = frozenset({"pause", "resume", "retry", "cancel"})
_OUTCOMES = frozenset({"applied", "noop"})
_STATUSES = frozenset({"planned", "running", "waiting", "finished", "failed", "cancelled"})
_MAX_EVENTS = 64


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_state(value: Any) -> str:
    """Return the canonical digest used to bind a receipt to derived state."""
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def validate_identity(value: Any, field: str = "identity") -> str:
    """Validate and return an identity usable in a control receipt."""
    return _require_id(value, field)


def _require_positive(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


def _require_status(value: Any, field: str) -> str:
    if value not in _STATUSES:
        raise ValueError(f"{field} is invalid")
    return value


def _require_ids(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > _MAX_EVENTS:
        raise ValueError(f"{field} must be a bounded list")
    result = tuple(_require_id(item, f"{field}[{index}]") for index, item in enumerate(value))
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicates")
    return result


def _require_sequences(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list) or len(value) > _MAX_EVENTS:
        raise ValueError("event_sequences must be a bounded list")
    result = tuple(_require_positive(item, f"event_sequences[{index}]") for index, item in enumerate(value))
    if tuple(sorted(result)) != result or len(set(result)) != len(result):
        raise ValueError("event_sequences must be strictly increasing")
    return result


@dataclass(frozen=True)
class ControlReceipt:
    """Causal summary of one local lifecycle control projection."""

    schema_version: str
    receipt_id: str
    command_id: str
    run_id: str
    actor_id: str
    operation: str
    requested_at: int
    outcome: str
    before_status: str
    after_status: str
    before_sequence: int
    after_sequence: int
    event_ids: tuple[str, ...]
    event_sequences: tuple[int, ...]
    state_digest: str

    _fields: ClassVar[tuple[str, ...]] = (
        "schema_version",
        "receipt_id",
        "command_id",
        "run_id",
        "actor_id",
        "operation",
        "requested_at",
        "outcome",
        "before_status",
        "after_status",
        "before_sequence",
        "after_sequence",
        "event_ids",
        "event_sequences",
        "state_digest",
    )

    def __post_init__(self) -> None:
        if self.schema_version != CONTROL_RECEIPT_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CONTROL_RECEIPT_SCHEMA_VERSION}")
        for field in ("receipt_id", "command_id", "run_id", "actor_id"):
            _require_id(getattr(self, field), field)
        if self.operation not in _OPERATIONS:
            raise ValueError("operation is invalid")
        if self.outcome not in _OUTCOMES:
            raise ValueError("outcome is invalid")
        _require_positive(self.requested_at, "requested_at")
        _require_status(self.before_status, "before_status")
        _require_status(self.after_status, "after_status")
        if isinstance(self.before_sequence, bool) or not isinstance(self.before_sequence, int) or self.before_sequence < 0:
            raise ValueError("before_sequence is invalid")
        _require_positive(self.after_sequence, "after_sequence")
        if not isinstance(self.event_ids, (list, tuple)):
            raise ValueError("event_ids must be a bounded list")
        if not isinstance(self.event_sequences, (list, tuple)):
            raise ValueError("event_sequences must be a bounded list")
        event_ids = _require_ids(list(self.event_ids), "event_ids")
        event_sequences = _require_sequences(list(self.event_sequences))
        if len(event_ids) != len(event_sequences):
            raise ValueError("event_ids and event_sequences must have equal lengths")
        if self.before_sequence > self.after_sequence:
            raise ValueError("before_sequence cannot exceed after_sequence")
        if self.outcome == "noop":
            if event_ids:
                raise ValueError("noop receipt cannot contain events")
            if self.before_sequence != self.after_sequence:
                raise ValueError("noop receipt sequence must not change")
            if self.before_status != self.after_status:
                raise ValueError("noop receipt status must not change")
        else:
            if not event_ids:
                raise ValueError("applied receipt must contain events")
            expected_sequences = tuple(
                range(self.before_sequence + 1, self.after_sequence + 1)
            )
            if event_sequences != expected_sequences:
                raise ValueError("applied receipt event sequences must be contiguous")
        _require_digest(self.state_digest, "state_digest")
        object.__setattr__(self, "event_ids", event_ids)
        object.__setattr__(self, "event_sequences", event_sequences)

    @classmethod
    def from_dict(cls, value: Any) -> "ControlReceipt":
        if not isinstance(value, Mapping):
            raise ValueError("control receipt must be an object")
        expected = set(cls._fields)
        actual = set(value)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing:
            raise ValueError(f"control receipt missing fields: {', '.join(missing)}")
        if unknown:
            raise ValueError(f"control receipt has unknown fields: {', '.join(unknown)}")
        return cls(
            schema_version=value["schema_version"],
            receipt_id=value["receipt_id"],
            command_id=value["command_id"],
            run_id=value["run_id"],
            actor_id=value["actor_id"],
            operation=value["operation"],
            requested_at=value["requested_at"],
            outcome=value["outcome"],
            before_status=value["before_status"],
            after_status=value["after_status"],
            before_sequence=value["before_sequence"],
            after_sequence=value["after_sequence"],
            event_ids=value["event_ids"],
            event_sequences=value["event_sequences"],
            state_digest=value["state_digest"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "command_id": self.command_id,
            "run_id": self.run_id,
            "actor_id": self.actor_id,
            "operation": self.operation,
            "requested_at": self.requested_at,
            "outcome": self.outcome,
            "before_status": self.before_status,
            "after_status": self.after_status,
            "before_sequence": self.before_sequence,
            "after_sequence": self.after_sequence,
            "event_ids": list(self.event_ids),
            "event_sequences": list(self.event_sequences),
            "state_digest": self.state_digest,
        }

    def canonical_json(self) -> bytes:
        """Return deterministic receipt bytes for an outer signer or store."""
        return _canonical_json(self.to_dict())

    def verify_state(self, state: Any) -> bool:
        """Return whether a replayed state matches this receipt's digest."""
        return digest_state(state) == self.state_digest
