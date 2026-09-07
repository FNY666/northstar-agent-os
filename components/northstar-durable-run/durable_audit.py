"""Bridge EventStore events into the canonical NDJSON audit feed (audit v1).

``northstar-durable-run`` depends on ``northstar-run-contract``, so this
adapter uses the contract's ``audit`` module as its single source of truth for
the envelope: an EventStore event (``EventContract``) becomes one audit
record with the durable event identity preserved inside ``payload``.
"""
from __future__ import annotations

from typing import Any, Iterable, Iterator

from audit import new_record, to_ndjson

COMPONENT = "northstar-durable-run"

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
