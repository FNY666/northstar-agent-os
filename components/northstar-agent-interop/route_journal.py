"""Append-only, replay-safe journal for deterministic route decisions."""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Literal

SCHEMA_VERSION = "northstar.route-journal.v1"
_STATUS = ("selected", "failed")
_FAILURE_CLASSES = frozenset({
    "no_candidate", "capability_mismatch", "disabled", "unhealthy",
    "cooldown", "identity_mismatch", "deadline_invalid", "policy_stale",
    "malformed_request", "replay_conflict",
})
_RECORD_FIELDS = frozenset({
    "schema_version", "idempotency_key", "request_digest", "policy_revision",
    "status", "failure_class", "selected_agent_id", "selected_provider",
    "deadline_at", "candidate_snapshot",
})
_CANDIDATE_FIELDS = frozenset({
    "agent_id", "provider", "version", "enabled", "health",
    "cooldown_until", "priority", "capabilities",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

class JournalError(ValueError):
    """Base class for malformed or conflicting journal state."""

class JournalConflict(JournalError):
    """The same idempotency key was used with different canonical input."""

class RouteSelectionError(JournalError):
    """The route cannot be replayed or is incompatible with a handoff."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JournalError("value is not canonical JSON") from exc


def _check_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise JournalError(f"{field} is invalid")
    return value


def _check_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise JournalError(f"{field} is invalid")
    return value


def _candidate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _CANDIDATE_FIELDS:
        raise JournalError("candidate snapshot has unknown or missing fields")
    agent_id = _check_id(value["agent_id"], "candidate agent_id")
    provider = _check_id(value["provider"], "candidate provider")
    version = _check_id(value["version"], "candidate version")
    if not isinstance(value["enabled"], bool):
        raise JournalError("candidate enabled must be boolean")
    health = value["health"]
    if health not in {"healthy", "degraded", "unhealthy", "unknown"}:
        raise JournalError("candidate health is invalid")
    cooldown = value["cooldown_until"]
    if not isinstance(cooldown, int) or isinstance(cooldown, bool) or cooldown < 0:
        raise JournalError("candidate cooldown_until is invalid")
    priority = value["priority"]
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise JournalError("candidate priority is invalid")
    capabilities = value["capabilities"]
    if (not isinstance(capabilities, list) or
            not all(isinstance(item, str) and ":" in item and "*" not in item for item in capabilities) or
            len(set(capabilities)) != len(capabilities)):
        raise JournalError("candidate capabilities are invalid")
    return {
        "agent_id": agent_id, "provider": provider, "version": version,
        "enabled": value["enabled"], "health": health,
        "cooldown_until": cooldown, "priority": priority,
        "capabilities": sorted(capabilities),
    }

@dataclass(frozen=True)
class RouteJournalRecord:
    schema_version: str
    idempotency_key: str
    request_digest: str
    policy_revision: str
    status: Literal["selected", "failed"]
    failure_class: str | None
    selected_agent_id: str | None
    selected_provider: str | None
    deadline_at: int | None
    candidate_snapshot: tuple[dict[str, Any], ...]

    @classmethod
    def from_dict(cls, value: Any) -> "RouteJournalRecord":
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise JournalError("route journal record has unknown or missing fields")
        if value["schema_version"] != SCHEMA_VERSION:
            raise JournalError("route journal schema_version is invalid")
        idem = _check_id(value["idempotency_key"], "idempotency_key")
        digest = _check_digest(value["request_digest"], "request_digest")
        policy = _check_id(value["policy_revision"], "policy_revision")
        status = value["status"]
        if status not in _STATUS:
            raise JournalError("route journal status is invalid")
        failure = value["failure_class"]
        if failure is not None and failure not in _FAILURE_CLASSES:
            raise JournalError("route journal failure_class is invalid")
        selected_agent = value["selected_agent_id"]
        selected_provider = value["selected_provider"]
        if (selected_agent is None) != (selected_provider is None):
            raise JournalError("selected identity must be complete")
        if selected_agent is not None:
            _check_id(selected_agent, "selected_agent_id")
            _check_id(selected_provider, "selected_provider")
        deadline = value["deadline_at"]
        if deadline is not None and (not isinstance(deadline, int) or isinstance(deadline, bool) or deadline < 0):
            raise JournalError("deadline_at is invalid")
        snapshot = value["candidate_snapshot"]
        if not isinstance(snapshot, list) or len(snapshot) > 256:
            raise JournalError("candidate_snapshot is invalid")
        candidates = tuple(_candidate(item) for item in snapshot)
        if status == "selected":
            if selected_agent is None or deadline is None or failure is not None:
                raise JournalError("selected record has inconsistent result fields")
        elif selected_agent is not None or deadline is not None or failure is None:
            raise JournalError("failed record has inconsistent result fields")
        return cls(SCHEMA_VERSION, idem, digest, policy, status, failure,
                   selected_agent, selected_provider, deadline, candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "idempotency_key": self.idempotency_key,
            "request_digest": self.request_digest,
            "policy_revision": self.policy_revision,
            "status": self.status,
            "failure_class": self.failure_class,
            "selected_agent_id": self.selected_agent_id,
            "selected_provider": self.selected_provider,
            "deadline_at": self.deadline_at,
            "candidate_snapshot": [dict(item) for item in self.candidate_snapshot],
        }

    def canonical_json(self) -> bytes:
        return _canonical(self.to_dict())


def decision_fingerprint(record: RouteJournalRecord) -> str:
    return "sha256:" + hashlib.sha256(record.canonical_json()).hexdigest()

class RouteDecisionJournal:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if self.path.exists():
            os.chmod(self.path, 0o600)

    def read(self) -> Iterator[RouteJournalRecord]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.endswith("\n"):
                    continue
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise JournalError("complete journal line is invalid JSON") from exc
                yield RouteJournalRecord.from_dict(value)

    def get_by_idempotency(self, key: str) -> RouteJournalRecord | None:
        _check_id(key, "idempotency_key")
        return next((record for record in self.read() if record.idempotency_key == key), None)

    def append(self, record: RouteJournalRecord) -> RouteJournalRecord:
        if not isinstance(record, RouteJournalRecord):
            raise JournalError("record has invalid type")
        previous = self.get_by_idempotency(record.idempotency_key)
        if previous is not None:
            if previous.canonical_json() != record.canonical_json():
                raise JournalConflict("idempotency key conflicts with existing decision")
            return previous
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.canonical_json().decode("utf-8") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        return record

__all__ = ["JournalConflict", "JournalError", "RouteDecisionJournal", "RouteJournalRecord", "SCHEMA_VERSION", "decision_fingerprint"]


def _request_digest(request: dict[str, Any]) -> str:
    digest = request.get("request_digest")
    if not isinstance(digest, str):
        raise RouteSelectionError("request_digest is required")
    return _check_digest(digest, "request_digest")


def _snapshot(router: Any, request: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = router.snapshot(request)
    if not isinstance(candidates, list):
        candidates = list(candidates)
    return [_candidate(item) for item in candidates]


def _record_from_selection(request: dict[str, Any], snapshot: list[dict[str, Any]],
                           selection: dict[str, Any], *, policy_revision: str) -> RouteJournalRecord:
    if not isinstance(selection, dict) or selection.get("status") not in {"selected", "failed"}:
        raise RouteSelectionError("router returned an invalid selection")
    status = selection["status"]
    failure = selection.get("failure_class")
    if status == "failed":
        return RouteJournalRecord.from_dict({
            "schema_version": SCHEMA_VERSION,
            "idempotency_key": request["idempotency_key"],
            "request_digest": _request_digest(request),
            "policy_revision": policy_revision,
            "status": "failed", "failure_class": failure,
            "selected_agent_id": None, "selected_provider": None,
            "deadline_at": None, "candidate_snapshot": snapshot,
        })
    agent = selection.get("agent_id"); provider = selection.get("provider")
    deadline = selection.get("deadline_at")
    return RouteJournalRecord.from_dict({
        "schema_version": SCHEMA_VERSION,
        "idempotency_key": request["idempotency_key"],
        "request_digest": _request_digest(request),
        "policy_revision": policy_revision,
        "status": "selected", "failure_class": None,
        "selected_agent_id": agent, "selected_provider": provider,
        "deadline_at": deadline, "candidate_snapshot": snapshot,
    })


def record_route(journal: RouteDecisionJournal, router: Any, request: dict[str, Any], *,
                 now: int, policy_revision: str, idempotency_key: str) -> RouteJournalRecord:
    if not isinstance(request, dict):
        raise RouteSelectionError("route request must be an object")
    request = dict(request)
    request["idempotency_key"] = idempotency_key
    existing = journal.get_by_idempotency(idempotency_key)
    if existing is not None:
        return existing
    snapshot = _snapshot(router, request)
    try:
        selection = router.select(request, now=now, policy_revision=policy_revision)
        record = _record_from_selection(request, snapshot, selection, policy_revision=policy_revision)
    except JournalError:
        raise
    except Exception as exc:
        record = RouteJournalRecord.from_dict({
            "schema_version": SCHEMA_VERSION,
            "idempotency_key": idempotency_key,
            "request_digest": _request_digest(request),
            "policy_revision": policy_revision,
            "status": "failed", "failure_class": "no_candidate",
            "selected_agent_id": None, "selected_provider": None,
            "deadline_at": None, "candidate_snapshot": snapshot,
        })
    return journal.append(record)


def replay_route(journal: RouteDecisionJournal, router: Any, record: RouteJournalRecord,
                 request: dict[str, Any], *, now: int, policy_revision: str) -> RouteJournalRecord:
    if not isinstance(record, RouteJournalRecord):
        raise RouteSelectionError("route journal record has invalid type")
    if policy_revision != record.policy_revision:
        raise RouteSelectionError("route policy revision changed")
    if _request_digest(request) != record.request_digest:
        raise RouteSelectionError("route request digest changed")
    stored = journal.get_by_idempotency(record.idempotency_key)
    if stored is None or stored.canonical_json() != record.canonical_json():
        raise RouteSelectionError("journal record is not the stored decision")
    current_snapshot = _snapshot(router, request)
    if current_snapshot != list(record.candidate_snapshot):
        raise RouteSelectionError("candidate snapshot changed")
    selection = router.select(request, now=now, policy_revision=policy_revision)
    recomputed = _record_from_selection({**request, "idempotency_key": record.idempotency_key}, current_snapshot,
                                        selection, policy_revision=policy_revision)
    if decision_fingerprint(recomputed) != decision_fingerprint(record):
        raise RouteSelectionError("route decision fingerprint changed")
    return record


def assert_handoff_compatible(record: RouteJournalRecord, handoff: dict[str, Any]) -> None:
    if record.status != "selected":
        raise RouteSelectionError("failed route cannot authorize a handoff")
    if not isinstance(handoff, dict):
        raise RouteSelectionError("handoff must be an object")
    if handoff.get("target_agent_id") != record.selected_agent_id or handoff.get("provider") != record.selected_provider:
        raise RouteSelectionError("handoff identity does not match route decision")
    deadline = handoff.get("deadline_at")
    if not isinstance(deadline, int) or record.deadline_at is None or deadline > record.deadline_at:
        raise RouteSelectionError("handoff deadline must narrow the route deadline")

__all__ += ["RouteSelectionError", "assert_handoff_compatible", "record_route", "replay_route"]
