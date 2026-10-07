"""Traceability paradox detector: the safety instrument as attack surface.

Research basis (second-hand):
- infosec.ch op-ed (Oct 2026): accountability/self-monitoring mechanisms as
  attack objects. The thesis is the paradox in the name: the very audit log
  that is supposed to prove what happened is the thing a compromised agent
  rewrites first. "The safety instrument is the attack surface" - this is the
  second independent formulation of the datum (the first was the docker.sock
  write-up in the interpretability line).
- Verified counterpart: the DurableAuditWriter / METR Inspect "Potemkin
  village" PoC pattern (display layer hijacked while the database stays
  clean) - manipulation happens at the seam between observation and record.

Design: structural integrity checks over a host-reported audit log (a list of
record mappings). The detector names the structural failure; the gate layer
decides what to do with the verdict:

- GAP: the ``seq`` field skips integers (records deleted/omitted), or repeats
  (replay). Sequence numbers are the cheapest place to hide a deletion.
- REORDER: ``ts`` timestamps are not non-decreasing (history re-sequenced).
- HASH_BREAK: the hash chain does not verify - a record's ``prev_hash`` does
  not match the previous record's ``chain_hash``, or its ``chain_hash`` does
  not recompute to ``sha256(raw(prev_hash) || canonical(body))``.

Detector, not defense: it flags *that* the log's structure was tampered
with, not *why*, and it cannot see an attack that leaves the structure
intact (a wholesale rewrite with a fresh, internally-consistent chain).
That case needs an external head anchor (see audit_chain.anchor_manifest).

Honest scope: structural only. It verifies links, monotonicity, and
contiguity; it does not parse intent, understand novel tamper shapes, or
distinguish an attacker from a buggy writer. A clean scan means "no known
structural break", never "no tampering".

No wall-clock anywhere. All functions are pure over the records given.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Version pin for the detector described here.
TRACEABILITY_PARADOX_VERSION = "traceability-paradox.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.traceability-paradox.v1"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

#: Seal fields excluded from the hashed body (the seal itself / the
#: signature over the seal), mirroring audit_chain._SEAL_FIELDS.
_SEAL_FIELDS = ("prev_hash", "chain_hash", "signature")


class ParadoxType(Enum):
    """The three structural tamper shapes this module detects."""

    GAP = "gap"
    REORDER = "reorder"
    HASH_BREAK = "hash-break"


class TraceabilityParadoxError(ValueError):
    """Malformed audit-log input."""


@dataclass(frozen=True)
class ParadoxFinding:
    """One structural break in the audit log."""

    index: int
    paradox_type: ParadoxType
    detail: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError("index must be an integer")
        if self.index < 0:
            raise ValueError("index must be non-negative")
        if not isinstance(self.paradox_type, ParadoxType):
            raise TypeError("paradox_type must be a ParadoxType")
        if not self.detail or not isinstance(self.detail, str):
            raise ValueError("detail must be a non-empty string")


def _check_log(records: Any) -> Sequence[Mapping[str, Any]]:
    """Validate the log shape; raise TypeError on malformed input."""
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise TypeError("audit log must be a sequence of record mappings")
    for i, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise TypeError(f"record at index {i} is not a mapping")
    return records


def _check_hash_link(records: Sequence[Mapping[str, Any]], i: int) -> Optional[str]:
    """Return a detail string if record i's chain link is broken, else None."""
    record = records[i]
    prev_hash = record.get("prev_hash")
    chain_hash = record.get("chain_hash")
    if prev_hash is None and chain_hash is None:
        return None  # not a chained record; nothing to verify
    if prev_hash is None or chain_hash is None:
        return "record carries a partial seal (prev_hash/chain_hash missing)"
    if not isinstance(prev_hash, str) or not _HEX64_RE.match(prev_hash):
        return "prev_hash is not 64 lowercase hex characters"
    if not isinstance(chain_hash, str) or not _HEX64_RE.match(chain_hash):
        return "chain_hash is not 64 lowercase hex characters"
    if i == 0:
        expected_prev = None
    else:
        prev_record = records[i - 1]
        expected_prev = prev_record.get("chain_hash")
    if expected_prev is not None and not (
        isinstance(expected_prev, str)
        and hmac.compare_digest(expected_prev, prev_hash)
    ):
        return (
            f"prev_hash does not match the previous record's chain_hash "
            f"(index {i - 1})"
        )
    body = {k: v for k, v in record.items() if k not in _SEAL_FIELDS}
    recomputed = hashlib.sha256(
        bytes.fromhex(prev_hash) + jcs_canonical_json(body)
    ).hexdigest()
    if not hmac.compare_digest(recomputed, chain_hash):
        return "chain_hash does not recompute from prev_hash and body"
    return None


def _find_gaps(records: Sequence[Mapping[str, Any]]) -> list[Tuple[int, str]]:
    """Return (index, detail) for sequence-number anomalies."""
    seqs: list[Tuple[int, int]] = []
    for i, record in enumerate(records):
        seq = record.get("seq")
        if seq is None:
            return []  # seq-based checks need seq on every record
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TraceabilityParadoxError(
                f"record at index {i} has a non-integer seq"
            )
        seqs.append((i, seq))
    findings: list[Tuple[int, str]] = []
    seen: dict[int, int] = {}
    for i, seq in seqs:
        if seq in seen:
            findings.append(
                (i, f"duplicate seq {seq} (first seen at index {seen[seq]})")
            )
        else:
            seen[seq] = i
    if seen:
        lo, hi = min(seen), max(seen)
        missing = [s for s in range(lo, hi + 1) if s not in seen]
        if missing:
            findings.append(
                (
                    0,
                    f"seq gap: missing seq numbers {missing} in range {lo}..{hi}",
                )
            )
    return findings


def _ts_key(value: Any) -> Tuple[int, Any]:
    """Return a sortable key for a timestamp value.

    Numbers sort by value (rank 0), ISO-8601-shaped strings parse to epoch
    (rank 0 as well, directly comparable), anything else falls back to its
    string form (rank 1, lexicographic - strictly a best effort).
    """
    if isinstance(value, bool):
        raise TraceabilityParadoxError("ts must not be a boolean")
    if isinstance(value, (int, float)):
        return (0, float(value))
    if isinstance(value, str):
        text = value.strip()
        parsed: Optional[float] = None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            dt = None
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed = dt.timestamp()
            return (0, parsed)
        return (1, text)
    raise TraceabilityParadoxError(
        f"ts of type {type(value).__name__} is not comparable"
    )


def _find_reorders(records: Sequence[Mapping[str, Any]]) -> list[Tuple[int, str]]:
    """Return (index, detail) for timestamp-order violations."""
    if not records:
        return []
    if any("ts" not in record for record in records):
        return []  # ts checks need ts on every record
    keys = [_ts_key(record["ts"]) for record in records]
    findings: list[Tuple[int, str]] = []
    for i in range(1, len(records)):
        if keys[i] < keys[i - 1]:
            findings.append(
                (
                    i,
                    f"ts out of order: record {i} sorts before record {i - 1}",
                )
            )
    return findings


def scan_paradoxes(audit_log: Sequence[Mapping[str, Any]]) -> list[ParadoxFinding]:
    """Return every structural paradox found in the log, in document order.

    Fixed severity order for classify-style consumers: HASH_BREAK issues
    sort before GAP issues before REORDER issues at the same index.
    """
    records = _check_log(audit_log)
    hash_issues: list[ParadoxFinding] = []
    for i in range(len(records)):
        detail = _check_hash_link(records, i)
        if detail is not None:
            hash_issues.append(
                ParadoxFinding(index=i, paradox_type=ParadoxType.HASH_BREAK,
                               detail=detail)
            )
    gap_issues = [
        ParadoxFinding(index=i, paradox_type=ParadoxType.GAP, detail=detail)
        for i, detail in _find_gaps(records)
    ]
    reorder_issues = [
        ParadoxFinding(index=i, paradox_type=ParadoxType.REORDER, detail=detail)
        for i, detail in _find_reorders(records)
    ]
    return sorted(
        hash_issues + gap_issues + reorder_issues,
        key=lambda f: (f.index, _SEVERITY_RANK[f.paradox_type]),
    )


def detect_paradox(audit_log: Sequence[Mapping[str, Any]]) -> bool:
    """True if the audit log shows any traceability paradox."""
    return len(scan_paradoxes(audit_log)) > 0


_SEVERITY_RANK = {
    ParadoxType.HASH_BREAK: 0,
    ParadoxType.GAP: 1,
    ParadoxType.REORDER: 2,
}


def classify_paradox(
    audit_log: Sequence[Mapping[str, Any]],
) -> Optional[ParadoxType]:
    """The most severe paradox type present, or None when the log is clean."""
    findings = scan_paradoxes(audit_log)
    if not findings:
        return None
    return min(findings, key=lambda f: _SEVERITY_RANK[f.paradox_type]).paradox_type


def paradox_audit_event(
    findings: Sequence[ParadoxFinding], seq: int
) -> dict[str, Any]:
    """Shape a detection result for the ``audit.ndjson/1`` envelope."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise TraceabilityParadoxError("seq must be a non-negative integer")
    return {
        "schema": SCHEMA_PIN,
        "seq": seq,
        "detector": TRACEABILITY_PARADOX_VERSION,
        "paradox_found": len(findings) > 0,
        "findings": [
            {
                "index": f.index,
                "type": f.paradox_type.value,
                "detail": f.detail,
            }
            for f in findings
        ],
    }


def _seal_for_test(body: dict[str, Any], prev_hash: str) -> dict[str, Any]:
    """Build a correctly chained record (test/fixture helper, not public)."""
    clean = {k: v for k, v in body.items() if k not in _SEAL_FIELDS}
    chain_hash = hashlib.sha256(
        bytes.fromhex(prev_hash) + jcs_canonical_json(clean)
    ).hexdigest()
    return {**clean, "prev_hash": prev_hash, "chain_hash": chain_hash}


def main() -> None:
    """Self-check: build a clean log, a tampered log, and scan both."""
    genesis = "00" * 32
    clean = [
        _seal_for_test({"seq": 1, "ts": "2026-10-07T20:00:00", "action": "open"}, genesis),
    ]
    prev = clean[0]["chain_hash"]
    clean.append(
        _seal_for_test({"seq": 2, "ts": "2026-10-07T20:00:01", "action": "read"}, prev)
    )
    prev = clean[1]["chain_hash"]
    clean.append(
        _seal_for_test({"seq": 3, "ts": "2026-10-07T20:00:02", "action": "close"}, prev)
    )
    assert not detect_paradox(clean), "clean log must not fire"

    tampered = [dict(r) for r in clean]
    tampered[1] = dict(tampered[1])
    tampered[1]["seq"] = 99  # gap: 1, 99, 3
    findings = scan_paradoxes(tampered)
    assert any(f.paradox_type is ParadoxType.GAP for f in findings), "gap not found"
    assert any(f.paradox_type is ParadoxType.HASH_BREAK for f in findings), (
        "hash break not found after seq edit"
    )
    print(
        f"traceability-paradox OK: clean log silent, "
        f"tampered log -> {[f.paradox_type.value for f in findings]}"
    )


if __name__ == "__main__":
    main()
