"""Canonical audit feed: NDJSON v1 envelope shared by every Northstar producer.

The audit feed is the machine boundary between the repository's append-only
records and a SIEM/analytics pipeline: each line is one self-describing,
versioned record whose envelope is validated strictly (unknown envelope fields
are rejected, so adding a field is a schema revision, not a silent drift).

Producers and their mapping entry points:

* ``northstar-agent-runtime`` - ``audit_export.py`` mirrors this envelope
  locally (the runtime is intentionally dependency-free) and exports session
  transcripts; normative spec: docs/concepts/audit-trail.md.
* ``northstar-durable-run`` - ``durable_audit.event_to_audit`` maps EventStore
  events.
* ``northstar-host`` - ``host_audit.authorization_to_audit`` maps signed
  authorization grants.

Envelope v1 (``audit.ndjson/1``):

* required: ``schema_version``, ``component``, ``event``, ``ts`` (RFC 3339
  UTC, second or millisecond precision, ``Z`` suffix), ``level``
  (``info`` | ``notice`` | ``error``), ``payload`` (object).
* optional: ``seq`` (non-negative int), ``session_id``/``run_id``/``actor_id``
  (strings). No other keys are allowed.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Iterable, Iterator

AUDIT_SCHEMA_VERSION = "audit.ndjson/1"

LEVELS: tuple[str, ...] = ("info", "notice", "error")

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
_REQUIRED: dict[str, type] = {
    "schema_version": str,
    "component": str,
    "event": str,
    "ts": str,
    "level": str,
    "payload": dict,
}
_OPTIONAL: dict[str, type] = {
    "seq": int,
    "session_id": str,
    "run_id": str,
    "actor_id": str,
}


def now_rfc3339(*, now: float | None = None) -> str:
    """RFC 3339 UTC timestamp with milliseconds, e.g. ``2026-09-07T03:04:05.123Z``."""
    seconds = time.time() if now is None else now
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return f"{base}.{int((seconds % 1) * 1000):03d}Z"


def rfc3339_from_epoch(epoch_seconds: int) -> str:
    """Convert an integer epoch-seconds timestamp into the feed's RFC 3339 form."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(int(epoch_seconds))) + ".000Z"


def new_record(
    component: str,
    event: str,
    *,
    seq: int | None = None,
    ts: str | None = None,
    level: str = "info",
    payload: dict[str, Any] | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Build one audit record; raises ``ValueError`` on the first validation error."""
    record: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "component": component,
        "event": event,
        "ts": ts if ts is not None else now_rfc3339(),
        "level": level,
        "payload": dict(payload or {}),
    }
    if seq is not None:
        record["seq"] = seq
    for key, value in (
        ("session_id", session_id),
        ("run_id", run_id),
        ("actor_id", actor_id),
    ):
        if value is not None:
            record[key] = value
    errors = validate_record(record)
    if errors:
        raise ValueError(errors[0])
    return record


def validate_record(record: Any) -> tuple[str, ...]:
    """Envelope validation errors (empty tuple when the record is valid)."""
    if not isinstance(record, dict):
        return ("audit record must be an object",)
    errors: list[str] = []
    unknown = sorted(set(record) - set(_REQUIRED) - set(_OPTIONAL))
    if unknown:
        errors.append(f"unknown audit envelope fields: {', '.join(unknown)}")
    for key, expected in _REQUIRED.items():
        if key not in record:
            errors.append(f"audit record is missing {key!r}")
        elif not isinstance(record[key], expected):
            errors.append(f"audit {key!r} must be {expected.__name__}")
    for key, expected in _OPTIONAL.items():
        if key in record and not isinstance(record[key], expected):
            errors.append(f"audit {key!r} must be {expected.__name__}")
    if "schema_version" in record and record["schema_version"] != AUDIT_SCHEMA_VERSION:
        errors.append(
            f"unsupported audit schema_version {record['schema_version']!r} "
            f"(this reader accepts {AUDIT_SCHEMA_VERSION!r} only)"
        )
    if "component" in record and (
        not isinstance(record["component"], str)
        or not re.match(r"^[a-z][a-z0-9-]*$", record["component"])
    ):
        errors.append("audit 'component' must be a lowercase name like 'northstar-agent-runtime'")
    if "event" in record and (
        not isinstance(record["event"], str) or not _ID_RE.match(record["event"])
    ):
        errors.append("audit 'event' must be a non-empty identifier")
    if "ts" in record and (not isinstance(record["ts"], str) or not _TS_RE.match(record["ts"])):
        errors.append("audit 'ts' must be an RFC 3339 UTC timestamp ending in 'Z'")
    if "level" in record and record["level"] not in LEVELS:
        errors.append(f"audit 'level' must be one of {', '.join(LEVELS)}")
    if "seq" in record and (not isinstance(record["seq"], int) or isinstance(record["seq"], bool) or record["seq"] < 0):
        errors.append("audit 'seq' must be a non-negative integer")
    for key in ("session_id", "run_id", "actor_id"):
        if key in record and (
            not isinstance(record[key], str) or not record[key] or len(record[key]) > 200
        ):
            errors.append(f"audit {key!r} must be a non-empty string of at most 200 characters")
    return tuple(errors)


def dumps_record(record: dict[str, Any]) -> str:
    """One canonical NDJSON line (no trailing newline); validates first."""
    errors = validate_record(record)
    if errors:
        raise ValueError(errors[0])
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def to_ndjson(records: Iterable[dict[str, Any]]) -> str:
    """Canonical NDJSON text for many records (each line ends with a newline)."""
    return "".join(dumps_record(record) + "\n" for record in records)


def iter_ndjson(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Parse NDJSON text lines into validated audit records.

    Blank lines are skipped; a damaged line raises ``ValueError`` naming the
    line number - an audit feed must fail loudly, never silently drop records.
    """
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"audit line {number} is not valid JSON: {error}") from error
        errors = validate_record(record)
        if errors:
            raise ValueError(f"audit line {number} is invalid: {errors[0]}")
        yield record
