"""Export session transcripts as the canonical NDJSON audit feed (audit v1).

The runtime is deliberately dependency-free, so it does not import
``northstar-run-contract.audit``; this module mirrors that envelope spec (the
normative description lives in docs/concepts/audit-trail.md, and the contract
component's ``audit.py`` is the validating implementation for the components
that may depend on it). Both sides pin the same ``AUDIT_SCHEMA_VERSION``.

Each transcript record (``{index, ts, session_id, type, ...payload}``) becomes
one audit line:

* ``event`` = the session record type (``session_start``, ``assistant``,
  ``tool_result``, ``denial``, ``result``, ...);
* ``seq`` = the record's transcript index;
* ``ts`` = the record's original RFC 3339 UTC timestamp (never re-stamped);
* ``level`` = ``error`` for denials, failed tool results and ``error_*``
  results, ``info`` otherwise;
* ``payload`` = everything the transcript record carried beyond the envelope.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from sessions import SESSION_FILE_SUFFIX, read_session_records

AUDIT_SCHEMA_VERSION = "audit.ndjson/1"
COMPONENT = "northstar-agent-runtime"

_ENVELOPE_KEYS = ("index", "ts", "session_id", "type")
_ERROR_TYPES = {"denial"}


def _record_level(record: dict[str, Any]) -> str:
    """error for denials, failed tool results and error results; else info."""
    kind = record.get("type", "")
    if kind in _ERROR_TYPES:
        return "error"
    if record.get("is_error") is True:
        return "error"
    if kind == "tool_result":
        # Real transcript shape: failed calls carry is_error inside content blocks.
        content = record.get("content")
        if isinstance(content, list) and any(
            isinstance(block, dict) and block.get("is_error") is True for block in content
        ):
            return "error"
    if kind == "result":
        subtype = record.get("subtype")
        if isinstance(subtype, str) and subtype.startswith("error"):
            return "error"
    if record.get("subtype") == "action_receipt":
        receipt = record.get("receipt")
        if isinstance(receipt, dict) and receipt.get("status") in {"denied", "failed"}:
            return "error"
    payload = record.get("payload")
    if isinstance(payload, dict) and payload.get("is_error") is True:
        return "error"
    return "info"


def record_to_audit(record: dict[str, Any]) -> dict[str, Any]:
    """Map one session transcript record to one canonical audit record."""
    for key in _ENVELOPE_KEYS:
        if key not in record:
            raise ValueError(f"session record is missing {key!r}; not a transcript record?")
    audit: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "component": COMPONENT,
        "event": record["type"],
        "seq": int(record["index"]),
        "ts": record["ts"],
        "level": _record_level(record),
        "payload": {key: value for key, value in record.items() if key not in _ENVELOPE_KEYS},
    }
    session_id = record.get("session_id")
    if isinstance(session_id, str) and session_id:
        audit["session_id"] = session_id
    return audit


def records_to_ndjson(records: Iterable[dict[str, Any]]) -> str:
    """Canonical NDJSON text for whole transcript records (newline-terminated)."""
    return "".join(
        json.dumps(
            record_to_audit(record),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for record in records
    )


def transcript_path_to_ndjson(path: Path) -> str:
    """Export one transcript file (``*.jsonl``) as canonical NDJSON audit text.

    Torn trailing lines are skipped exactly like the transcript reader skips
    them (expected after a crash); earlier corruption raises.
    """
    records, _dropped = read_session_records(path, lock=True)
    return records_to_ndjson(records)


def session_path(directory: Path, session_id: str) -> Path:
    """The transcript file for one session id (mirrors the session_view lookup)."""
    return directory / f"{session_id}{SESSION_FILE_SUFFIX}"
