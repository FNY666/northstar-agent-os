"""Bridge EventStore events into the canonical NDJSON audit feed (audit v1).

``northstar-durable-run`` depends on ``northstar-run-contract``, so this
adapter uses the contract's ``audit`` module as its single source of truth for
the envelope: an EventStore event (``EventContract``) becomes one audit
record with the durable event identity preserved inside ``payload``.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Iterator

from audit import new_record, to_ndjson
from blob_store import BlobStore
from durable_contract import EventContract
from evidence_contract import EvidenceRef, canonical_json, digest_subject
from evidence_store import EvidenceEntry, EvidenceStore

COMPONENT = "northstar-durable-run"

#: First-class tool-effect ledger events (see tool_ledger.py). They flow into
#: the audit feed under their own names — one record per ledger transition —
#: so a SIEM can track per-tool-effect started/completed/failed without
#: reading Northstar's event store.
TOOL_EVENT_TYPES = ("tool.started", "tool.completed", "tool.failed")

# EventContract dict keys that are not needed in the audit payload (they are
# carried by the envelope itself or are structural digests of the store).
_PAYLOAD_KEYS = (
    "event_id",
    "task_id",
    "thread_id",
    "run_id",
    "step_id",
    "event_type",
    "status",
    "idempotency_key",
    "trace_id",
    "payload_digest",
)

_ERROR_STATUS_SUFFIXES = ("failed", "denied", "error")


def _level_for_status(status: str) -> str:
    lowered = status.lower()
    return "error" if any(lowered.endswith(suffix) for suffix in _ERROR_STATUS_SUFFIXES) else "info"


def event_to_audit(event: dict[str, Any], *, occurred_at_is_ms: bool = False) -> dict[str, Any]:
    """Map one EventContract dict to a canonical audit record.

    ``occurred_at`` is epoch *seconds* in the durable-run fixtures; pass
    ``occurred_at_is_ms=True`` when the source emits milliseconds.
    """
    from audit import rfc3339_from_epoch

    occurred = int(event["occurred_at"])
    if occurred_at_is_ms:
        occurred, remainder = divmod(occurred, 1000)
        ts = rfc3339_from_epoch(occurred).replace(".000Z", f".{remainder:03d}Z")
    else:
        ts = rfc3339_from_epoch(occurred)
    payload = {key: event[key] for key in _PAYLOAD_KEYS if key in event}
    return new_record(
        COMPONENT,
        event.get("event_type", "event"),
        seq=int(event["sequence"]),
        ts=ts,
        level=_level_for_status(event.get("status", "")),
        payload=payload,
        run_id=event.get("run_id"),
    )


def events_to_ndjson(events: Iterable[dict[str, Any]]) -> str:
    """Export many events as one canonical NDJSON audit feed text."""
    return to_ndjson(event_to_audit(event) for event in events)


def iter_events_audit(events: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Lazily map many events into validated audit records."""
    for event in events:
        yield event_to_audit(event)


class DurableEvidenceSink:
    """Mirror one durable-run event stream into a dedicated evidence ledger.

    Each event becomes one hash-chained entry whose subject contains the
    validated event and canonical audit projection. Payload bytes are stored
    in EventStore's content-addressed blob area; the evidence entry carries a
    typed reference, not a second plaintext copy. Use a separate EvidenceStore
    for each run and do not mix other evidence sources into this ledger.
    """

    def __init__(self, store: EvidenceStore, *, artifact_store: BlobStore) -> None:
        if not isinstance(store, EvidenceStore):
            raise ValueError("store must be an EvidenceStore")
        if not isinstance(artifact_store, BlobStore):
            raise ValueError("artifact_store must be a BlobStore")
        self.store = store
        self.artifact_store = artifact_store
        self.run_id = store.run_id
        entries = store.entries
        for index, entry in enumerate(entries, start=1):
            if (
                entry.run_id != self.run_id
                or entry.sequence != index
                or entry.source != COMPONENT
                or entry.source_id != f"durable-event-{index}"
                or not entry.kind.startswith("durable.")
            ):
                raise ValueError(
                    "evidence ledger is not a contiguous durable-run sink for this run"
                )
            refs = {ref.kind: ref for ref in entry.refs}
            if len(refs) != len(entry.refs):
                raise ValueError("evidence entry contains duplicate durable artifact ref kinds")
            subject_ref = refs.get("durable-subject")
            if subject_ref is None:
                raise ValueError("evidence entry is missing its durable subject artifact ref")
            subject_bytes = artifact_store.get(subject_ref.digest)
            if digest_subject(subject_bytes) != entry.subject_digest:
                raise ValueError("durable subject artifact does not match evidence subject_digest")
            try:
                subject = json.loads(subject_bytes.decode("utf-8"))
                event = EventContract.from_dict(subject["durable_event"])
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                raise ValueError("durable subject artifact is malformed") from error
            if canonical_json(subject) != subject_bytes:
                raise ValueError("durable subject artifact is not canonical JSON")
            if subject_ref.ref_id != event.event_id:
                raise ValueError("durable subject artifact ref does not match its event_id")
            if event.run_id != self.run_id or event.sequence != index:
                raise ValueError("durable subject artifact does not match evidence sequence/run")
            if subject.get("audit_record") != event_to_audit(event.to_dict()):
                raise ValueError("durable subject audit projection does not match the event")
            payload_metadata = subject.get("payload")
            if not isinstance(payload_metadata, dict) or payload_metadata != {
                "available": event.blob_ref is not None,
                "blob_ref": event.blob_ref,
                "digest": event.payload_digest,
            }:
                raise ValueError("durable subject payload metadata does not match the event")
            if event.blob_ref is not None:
                payload_ref = refs.get("durable-payload")
                if (
                    payload_ref is None
                    or payload_ref.ref_id != event.event_id
                    or payload_ref.digest != event.blob_ref
                ):
                    raise ValueError("evidence entry is missing its durable payload artifact ref")
                payload_bytes = artifact_store.get(payload_ref.digest)
                digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
                if digest != event.payload_digest:
                    raise ValueError("durable payload artifact does not match event payload_digest")
            elif "durable-payload" in refs:
                raise ValueError("evidence entry has a payload ref for an event without a blob")
        self._last_sequence = len(entries)

    @property
    def last_sequence(self) -> int:
        """Highest mirrored durable event sequence; zero means an empty sink."""
        return self._last_sequence

    def append_event(
        self,
        event: EventContract,
        *,
        payload_bytes: bytes | None = None,
    ) -> EvidenceEntry:
        """Append one validated event and bind any durable payload blob by digest."""
        if not isinstance(event, EventContract):
            raise ValueError("event must be an EventContract")
        if event.run_id != self.run_id:
            raise ValueError("event run_id does not match evidence sink")
        if event.sequence > self._last_sequence + 1:
            raise ValueError("event sequence would leave a gap in the evidence sink")

        refs: list[EvidenceRef] = []
        payload_available = payload_bytes is not None
        if event.blob_ref is not None:
            if not isinstance(payload_bytes, bytes):
                raise ValueError("payload bytes are required to verify an event blob ref")
            payload_digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
            if payload_digest != event.payload_digest or payload_digest != event.blob_ref:
                raise ValueError("event payload bytes do not match payload_digest/blob_ref")
            refs.append(EvidenceRef("durable-payload", event.event_id, event.blob_ref))
        elif payload_bytes is not None:
            raise ValueError("payload bytes were supplied for an event without blob_ref")

        event_data = event.to_dict()
        subject = {
            "audit_record": event_to_audit(event_data),
            "durable_event": event_data,
            "payload": {
                "available": payload_available,
                "blob_ref": event.blob_ref,
                "digest": event.payload_digest,
            },
        }
        subject_bytes = canonical_json(subject)
        subject_ref = self.artifact_store.put(subject_bytes)
        if self.artifact_store.get(subject_ref) != subject_bytes:
            raise ValueError("durable subject artifact did not persist the expected bytes")
        refs.append(EvidenceRef("durable-subject", event.event_id, subject_ref))
        entry = self.store.append(
            source=COMPONENT,
            kind=f"durable.{event.event_type}",
            occurred_at=event.occurred_at,
            subject=subject_bytes,
            refs=refs,
            source_id=f"durable-event-{event.sequence}",
        )
        if entry.sequence != event.sequence:
            raise ValueError("evidence sequence does not match durable event sequence")
        self._last_sequence = max(self._last_sequence, event.sequence)
        return entry
