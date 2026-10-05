"""Seal the runtime's audit NDJSON feed into a tamper-evident evidence chain.

The agent runtime is deliberately dependency-free, so this adapter lives on
the *evidence* side: it reads the canonical audit NDJSON that
``northstar-agent-runtime.audit_export`` produces (``audit.ndjson/1``) and
appends each record to an :class:`EvidenceStore`, then seals the head.

One audit record becomes one evidence entry:

- ``source`` = ``"audit"`` (the fixed label for this adapter),
- ``kind`` = ``"audit.<event>"`` (e.g. ``audit.denial``),
- ``occurred_at`` = the record's ``ts`` parsed as a Unix epoch (strict
  ``YYYY-MM-DDTHH:MM:SS[.mmm]Z``; anything else is refused rather than
  guessed),
- ``subject`` = the full canonical audit record,
- ``source_id`` = ``"audit:<seq>"``, so re-sealing the same feed is
  idempotent instead of duplicating entries.

Honest limits: this proves the *exported feed* was not modified after
sealing. It does not prove the transcript the feed was exported from was
complete - a feed exported from a truncated transcript seals a truncated
history faithfully. Pair with the runtime's own transcript integrity checks
for the full story.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from evidence_contract import _identifier, canonical_json
from evidence_store import (
    EvidenceStore,
    ManifestVerification,
    SealSigner,
    SealVerifier,
)

AUDIT_SCHEMA_VERSION = "audit.ndjson/1"
AUDIT_SOURCE_LABEL = "audit"

_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
_EVENT_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def _epoch(ts: Any, *, seq: Any) -> int:
    """Parse the audit record's RFC 3339 UTC timestamp; refuse anything else."""
    if not isinstance(ts, str):
        raise ValueError(f"audit record seq {seq!r}: ts must be a string")
    for format in _TS_FORMATS:
        try:
            parsed = datetime.strptime(ts, format).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        epoch = int(parsed.timestamp())
        if epoch <= 0:
            raise ValueError(f"audit record seq {seq!r}: ts is out of range")
        return epoch
    raise ValueError(
        f"audit record seq {seq!r}: ts {ts!r} is not strict RFC 3339 UTC "
        "(expected YYYY-MM-DDTHH:MM:SS[.mmm]Z)"
    )


def _check_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("audit feed line is not a JSON object")
    if record.get("schema_version") != AUDIT_SCHEMA_VERSION:
        raise ValueError(
            f"audit record schema_version must be {AUDIT_SCHEMA_VERSION}"
        )
    event = record.get("event")
    if not isinstance(event, str) or not event:
        raise ValueError("audit record is missing a non-empty event")
    seq = record.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError("audit record seq must be a non-negative integer")
    return record


def parse_audit_feed(text: str) -> list[dict[str, Any]]:
    """Parse canonical audit NDJSON into validated record dicts.

    Blank lines are skipped. Any malformed line fails the whole feed rather
    than sealing a partial history silently.
    """
    if not isinstance(text, str):
        raise ValueError("audit feed must be text")
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"audit feed line {lineno} is not JSON: {error}") from error
        try:
            records.append(_check_record(record))
        except ValueError as error:
            raise ValueError(f"audit feed line {lineno}: {error}") from error
    return records


def seal_audit_feed(
    records: Iterable[Mapping[str, Any]],
    *,
    store_path: str,
    run_id: str,
    signer: SealSigner,
    sealed_at: int | None = None,
) -> dict[str, Any]:
    """Append an audit feed to an evidence store and seal the chain head.

    Returns the sealed manifest dict. Re-running over the same feed is
    idempotent (``source_id`` dedupe); new records extend the chain and
    re-sealing attests to the new head.
    """
    run_id = _identifier(run_id, "run_id")
    prepared: list[tuple[bytes, str, int, str]] = []
    previous_sequence: int | None = None
    for record in records:
        checked = _check_record(record)
        kind = f"audit.{checked['event']}"
        if not _EVENT_RE.fullmatch(kind):
            raise ValueError(f"audit event {checked['event']!r} is not a safe evidence kind")
        sequence = checked["seq"]
        if previous_sequence is not None and sequence <= previous_sequence:
            raise ValueError("audit feed seq values must be strictly increasing")
        occurred_at = _epoch(checked.get("ts"), seq=sequence)
        source_id = _identifier(f"audit:{sequence}", "source_id")
        # Run the canonical encoder before creating or modifying the store so
        # unsupported/oversized subjects cannot leave a partially sealed feed.
        subject_bytes = canonical_json(dict(checked))
        prepared.append((subject_bytes, kind, occurred_at, source_id))
        previous_sequence = sequence

    if not prepared:
        raise ValueError("refusing to seal an empty audit feed")

    store = EvidenceStore(store_path, run_id)
    for subject_bytes, kind, occurred_at, source_id in prepared:
        store.append(
            source=AUDIT_SOURCE_LABEL,
            kind=kind,
            occurred_at=occurred_at,
            subject=subject_bytes,
            source_id=source_id,
        )
    return store.seal(signer, sealed_at=sealed_at)


def verify_audit_seal(
    store_path: str,
    run_id: str,
    manifest: Mapping[str, Any],
    key_resolver: Mapping[str, SealVerifier],
) -> ManifestVerification:
    """Re-open the store (fail-closed on tamper) and verify the seal binds."""
    store = EvidenceStore(store_path, _identifier(run_id, "run_id"))
    return store.verify_seal(manifest, key_resolver)
