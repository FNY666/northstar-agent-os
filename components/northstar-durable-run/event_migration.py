"""Schema migration for the durable-run event history.

``audit.ndjson/1`` already versions its envelope with ``schema_version``;
this module extends the same discipline to the EventStore's internal event
types. Every schema revision ships with an upcaster: replay migrates each
stored event dict to the current revision *before* fold, so an old history
file is never rejected for being written by an older Northstar.

Rules, enforced by convention and tests:

- A revision bump is required for ANY event field change (add, remove,
  rename, type change). No silent drift.
- Upcasters are pure functions ``dict -> dict`` and must be total over the
  revision they claim: given any dict that validated under revision N, they
  return a dict that validates under revision N+1.
- Migration is in-memory only. The history file is append-only and is never
  rewritten; new appends always use the current revision.

Revision history
---------------
- ``northstar.durable-event.v1`` -> ``v2``: added the optional
  ``blob_ref`` field (``str | None``) for claim-check. The upcaster sets it
  to ``None``: v1 events never carried payloads out-of-band, so there is
  nothing to backfill.
"""
from __future__ import annotations

from typing import Any, Callable

from durable_contract import EVENT_SCHEMA_VERSION, EVENT_SCHEMA_VERSION_V1


def _upcast_event_v1_to_v2(value: dict[str, Any]) -> dict[str, Any]:
    """v1 -> v2: add ``blob_ref``.

    v1 events carried no out-of-band payload reference, so the only honest
    backfill is ``None`` — "this event's payload was inline-or-digest-only,
    there is no blob to point at". The field stays ``None`` on write for any
    payload under the claim-check threshold.
    """
    if "blob_ref" in value:
        raise ValueError("v1 event unexpectedly carries blob_ref")
    migrated = dict(value)
    migrated["blob_ref"] = None
    migrated["schema_version"] = EVENT_SCHEMA_VERSION
    return migrated


_UPCASTERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    EVENT_SCHEMA_VERSION_V1: _upcast_event_v1_to_v2,
}

_MAX_MIGRATION_STEPS = 16


def migrate_event_dict(value: Any) -> dict[str, Any]:
    """Migrate a stored event dict to the current event schema revision.

    Returns the (possibly copied) dict at ``EVENT_SCHEMA_VERSION``. Raises
    ``ValueError`` for a non-object, or for a schema_version that is neither
    current nor covered by an upcaster — an unknown revision is fail-closed,
    never passed through as if it were understood.
    """
    if not isinstance(value, dict):
        raise ValueError("event must be an object")
    current = dict(value)
    for _ in range(_MAX_MIGRATION_STEPS):
        version = current.get("schema_version")
        if version == EVENT_SCHEMA_VERSION:
            return current
        upcaster = _UPCASTERS.get(version) if isinstance(version, str) else None
        if upcaster is None:
            raise ValueError(
                f"event schema_version {version!r} is not current "
                f"({EVENT_SCHEMA_VERSION}) and has no upcaster: refusing to "
                "fold history written by an unknown schema"
            )
        current = upcaster(current)
    raise ValueError("event schema migration did not converge")
