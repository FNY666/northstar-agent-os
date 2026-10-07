"""Log-structured merge compaction for audit feeds.

Audit records arrive in *segments*: per-host shards, per-window chunks,
replicated tails redelivered after a restart. Segments overlap (duplicate
delivery), arrive out of order, and may carry divergent claims for the same
``seq``. ``AuditCompactor`` merges every segment into one ordered,
deduplicated, integrity-preserving stream:

1. **Segment-local integrity first** — each segment's hash-chain linkage is
   verified (``prev_hash``/``chain_hash`` per ``northstar-audit-chain/1``:
   ``chain_hash = sha256(raw(prev_hash) || canonical_json(body))``) before
   any of its records is admitted. A broken link raises
   :class:`ChainBrokenError`; nothing from a broken segment enters the
   merge. Records without chain fields are admitted as *unsealed* and
   counted in the report — they get no integrity claim.
2. **Dedup by byte identity** — only byte-identical records (same canonical
   digest) collapse. Two records claiming the same ``seq`` with different
   bodies are *conflicts*, not duplicates: compaction raises
   :class:`CompactionConflictError` naming every contested seq. History is
   never silently rewritten.
3. **Order by seq** — output is ordered by ``seq`` (ties broken
   deterministically by ``origin`` then digest). Missing seqs inside the
   covered range are reported as gaps, not filled.
4. **No rewriting** — compacted records are byte-identical to their inputs,
   so chain hashes stamped before compaction keep verifying after it. The
   :class:`CompactionReport` pins the input set and the output head so a
   verifier can re-derive both.

House style: stdlib-only (``hashlib``, ``json``, ``dataclasses``),
deterministic, no wall-clock (caller-supplied int seqs), fail-closed
validation (bool/negative/non-int seqs rejected), frozen records with
version/schema pins, ``main()`` self-check.

Honest scope: this merges *reported* records — it cannot see records a
host never sent, and a gap in ``seq`` means "not in the merged segments",
never "never happened". Chain verification is v1 topology only (legacy
canonicalization: sort_keys, compact separators); v2 (JCS) chained records
are admitted as unsealed unless their v1 recomputation happens to match.
Compaction pins what went in and what came out; it does not certify that
the inputs were complete or truthful. Large-integer caveat from
``canonical_json`` applies: ints beyond 2**53 lose precision under this
legacy canonicalization, so a record carrying such an int may digest
differently here than under JCS.

Version pin: audit-compaction.v1
Schema pin: northstar.audit-compaction.v1
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Tuple

#: Module version pin.
AUDIT_COMPACTION_VERSION = "audit-compaction.v1"

#: Schema pin for records and reports produced by this module.
SCHEMA_PIN = "northstar.audit-compaction.v1"

#: Chain seal fields (never hashed into the body they seal).
_SEAL_FIELDS = ("prev_hash", "chain_hash", "signature")

_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuditCompactionError(Exception):
    """Base error for audit compaction."""


class SegmentError(AuditCompactionError):
    """A segment is malformed or its records fail validation."""


class ChainBrokenError(AuditCompactionError):
    """A segment's hash-chain linkage does not verify."""


class CompactionConflictError(AuditCompactionError):
    """Two records claim the same seq with different bodies."""

    def __init__(self, message: str, seqs: Tuple[int, ...] = ()) -> None:
        super().__init__(message)
        self.seqs = seqs


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_int_seq(name: str, value: Any, *, allow_negative: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not allow_negative and value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _check_origin(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"origin must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError("origin must not be empty")
    return value


def _canonical_bytes(obj: Any) -> bytes:
    """Legacy v1 canonical bytes: sorted keys, compact, UTF-8."""
    try:
        text = json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"record body is not JSON-canonicalizable: {exc}") from exc
    return text.encode("utf-8")


def _record_digest(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _body_without_seal(record: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in record.items() if k not in _SEAL_FIELDS}


def _recompute_chain_hash(record: Mapping[str, Any]) -> str | None:
    """Recompute the v1 chain hash, or None when the record is unsealed."""
    prev = record.get("prev_hash")
    claimed = record.get("chain_hash")
    if prev is None or claimed is None:
        return None
    if not isinstance(prev, str) or not _HEX64_RE.match(prev):
        raise ChainBrokenError(f"prev_hash is not 64 hex chars: {prev!r}")
    if not isinstance(claimed, str) or not _HEX64_RE.match(claimed):
        raise ChainBrokenError(f"chain_hash is not 64 hex chars: {claimed!r}")
    body = _canonical_bytes(_body_without_seal(record))
    return hashlib.sha256(bytes.fromhex(prev) + body).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SegmentRecord:
    """One validated audit record with its canonical digest.

    ``body`` is a defensive copy of the input mapping; ``digest`` pins the
    canonical bytes. ``sealed`` is True when the record carries verifiable
    v1 chain fields.
    """

    seq: int
    origin: str
    body: Mapping[str, Any]
    digest: str
    sealed: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "seq": self.seq,
            "origin": self.origin,
            "body": dict(self.body),
            "digest": self.digest,
            "sealed": self.sealed,
        }


@dataclass
class AuditSegment:
    """A named, ordered collection of audit records from one producer.

    Records are appended in arrival order; linkage is checked by
    :meth:`verify_chain` (and again by the compactor before admission).
    """

    origin: str
    _records: List[SegmentRecord] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        _check_origin(self.origin)

    def append(self, record: Mapping[str, Any]) -> SegmentRecord:
        """Validate and stage one audit record (a mapping with an int ``seq``)."""
        if not isinstance(record, Mapping):
            raise SegmentError(
                f"record must be a mapping, got {type(record).__name__}")
        if "seq" not in record:
            raise SegmentError("record is missing 'seq'")
        seq = _check_int_seq("seq", record["seq"])
        body = dict(record)
        digest = _record_digest(body)
        sealed = _recompute_chain_hash(body) is not None
        staged = SegmentRecord(seq=seq, origin=self.origin, body=body,
                               digest=digest, sealed=sealed)
        self._records.append(staged)
        return staged

    def records(self) -> Tuple[SegmentRecord, ...]:
        return tuple(self._records)

    def verify_chain(self) -> Dict[str, Any]:
        """Check v1 linkage across the segment's sealed records.

        Returns ``{"ok": True, "sealed": n, "unsealed": m}``; raises
        :class:`ChainBrokenError` on the first broken link.
        """
        sealed = [r for r in self._records if r.sealed]
        for prev_rec, rec in zip(sealed, sealed[1:]):
            if rec.body.get("prev_hash") != prev_rec.body.get("chain_hash"):
                raise ChainBrokenError(
                    f"link broken at seq {rec.seq}: prev_hash does not match "
                    f"chain_hash of seq {prev_rec.seq}")
            if _recompute_chain_hash(rec.body) != rec.body.get("chain_hash"):
                raise ChainBrokenError(
                    f"chain_hash mismatch at seq {rec.seq}")
        if sealed:
            first = sealed[0]
            if _recompute_chain_hash(first.body) != first.body.get("chain_hash"):
                raise ChainBrokenError(
                    f"chain_hash mismatch at segment start seq {first.seq}")
        return {"ok": True, "sealed": len(sealed),
                "unsealed": len(self._records) - len(sealed)}

    def __len__(self) -> int:
        return len(self._records)


@dataclass(frozen=True)
class CompactionReport:
    """What compaction consumed, dropped, and produced (frozen)."""

    segments: int
    records_in: int
    duplicates_dropped: int
    unsealed_admitted: int
    records_out: int
    gaps: Tuple[int, ...]
    input_digest: str
    head_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "segments": self.segments,
            "records_in": self.records_in,
            "duplicates_dropped": self.duplicates_dropped,
            "unsealed_admitted": self.unsealed_admitted,
            "records_out": self.records_out,
            "gaps": list(self.gaps),
            "input_digest": self.input_digest,
            "head_digest": self.head_digest,
        }


@dataclass(frozen=True)
class CompactedFeed:
    """The merged, ordered, deduplicated record stream plus its report."""

    records: Tuple[SegmentRecord, ...]
    report: CompactionReport

    def seqs(self) -> Tuple[int, ...]:
        return tuple(r.seq for r in self.records)


# ---------------------------------------------------------------------------
# Compactor
# ---------------------------------------------------------------------------


class AuditCompactor:
    """Merges audit segments into one ordered, deduplicated feed."""

    def __init__(self) -> None:
        self._segments: List[AuditSegment] = []

    def add_segment(self, segment: AuditSegment) -> None:
        """Register a segment; its chain is verified before admission."""
        if not isinstance(segment, AuditSegment):
            raise TypeError(
                f"expected AuditSegment, got {type(segment).__name__}")
        segment.verify_chain()  # fail-closed: broken segments never enter
        self._segments.append(segment)

    def segments(self) -> Tuple[AuditSegment, ...]:
        return tuple(self._segments)

    def compact(self, seq: int) -> CompactedFeed:
        """Merge all registered segments. ``seq`` is the audit seq for the report.

        Fail-closed: any seq claimed by two non-identical records raises
        :class:`CompactionConflictError` — history is never silently
        rewritten.
        """
        _check_int_seq("seq", seq)
        staged: List[SegmentRecord] = []
        for segment in self._segments:
            staged.extend(segment.records())

        # Pin the input set before any reduction.
        input_digest = "sha256:" + hashlib.sha256(
            _canonical_bytes(sorted(r.digest for r in staged))).hexdigest()

        # Dedupe by byte identity.
        seen: Dict[str, SegmentRecord] = {}
        duplicates = 0
        for rec in staged:
            if rec.digest in seen:
                duplicates += 1
            else:
                seen[rec.digest] = rec
        unique = list(seen.values())

        # Conflict: same seq, different digest.
        by_seq: Dict[int, List[SegmentRecord]] = {}
        for rec in unique:
            by_seq.setdefault(rec.seq, []).append(rec)
        conflicts = sorted(s for s, rs in by_seq.items() if len(rs) > 1)
        if conflicts:
            raise CompactionConflictError(
                f"conflicting records at seq(s): {conflicts}",
                seqs=tuple(conflicts))

        # Deterministic order: seq, then origin, then digest.
        ordered = sorted(unique, key=lambda r: (r.seq, r.origin, r.digest))

        # Gaps inside the covered range.
        gaps: Tuple[int, ...] = ()
        if ordered:
            have = {r.seq for r in ordered}
            gaps = tuple(s for s in range(ordered[0].seq, ordered[-1].seq + 1)
                         if s not in have)

        unsealed = sum(1 for r in ordered if not r.sealed)
        head_digest = ordered[-1].digest if ordered else "sha256:" + "0" * 64

        report = CompactionReport(
            segments=len(self._segments),
            records_in=len(staged),
            duplicates_dropped=duplicates,
            unsealed_admitted=unsealed,
            records_out=len(ordered),
            gaps=gaps,
            input_digest=input_digest,
            head_digest=head_digest,
        )
        return CompactedFeed(records=tuple(ordered), report=report)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("segment-added", "compacted", "conflict", "chain-broken")


def audit_compaction_audit_event(kind: str, seq: int,
                                 report: CompactionReport | None = None,
                                 detail: str = "") -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for compaction decisions."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown kind: {kind!r}")
    _check_int_seq("seq", seq)
    if not isinstance(detail, str):
        raise TypeError("detail must be a str")
    event: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "audit_seq": seq,
    }
    if report is not None:
        if not isinstance(report, CompactionReport):
            raise TypeError(
                f"expected CompactionReport, got {type(report).__name__}")
        event["report"] = report.as_dict()
    if detail:
        event["detail"] = detail
    return event


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def _chain_pair(seq: int, prev_hash: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Build one v1-chained record dict for tests/self-check."""
    body = dict(payload)
    body["seq"] = seq
    body["prev_hash"] = prev_hash
    chain_hash = hashlib.sha256(
        bytes.fromhex(prev_hash) + _canonical_bytes(
            {k: v for k, v in body.items() if k not in _SEAL_FIELDS})).hexdigest()
    body["chain_hash"] = chain_hash
    return body


def main() -> None:
    """Self-check: segment chains, dedup, ordering, gaps, conflicts."""
    genesis = "ab" * 32
    compactor = AuditCompactor()

    seg_a = AuditSegment("host-a")
    r0 = seg_a.append(_chain_pair(0, genesis, {"kind": "boot"}))
    r1 = seg_a.append(_chain_pair(1, r0.body["chain_hash"], {"kind": "tick"}))
    assert seg_a.verify_chain()["sealed"] == 2

    seg_b = AuditSegment("host-b")
    seg_b.append(dict(r1.body))  # redelivered duplicate
    seg_b.append({"seq": 3, "kind": "note", "origin-note": "unsealed"})

    compactor.add_segment(seg_a)
    compactor.add_segment(seg_b)
    feed = compactor.compact(0)
    assert feed.seqs() == (0, 1, 3), feed.seqs()
    assert feed.report.records_in == 4
    assert feed.report.duplicates_dropped == 1
    assert feed.report.unsealed_admitted == 1
    assert feed.report.gaps == (2,), feed.report.gaps
    # Output records are byte-identical to inputs: chains still verify.
    for rec in feed.records:
        if rec.sealed:
            assert _recompute_chain_hash(rec.body) == rec.body["chain_hash"]

    # Conflict is fail-closed.
    bad = AuditCompactor()
    s1 = AuditSegment("x")
    s1.append({"seq": 0, "kind": "a"})
    s2 = AuditSegment("y")
    s2.append({"seq": 0, "kind": "b"})
    bad.add_segment(s1)
    bad.add_segment(s2)
    try:
        bad.compact(1)
    except CompactionConflictError as exc:
        assert exc.seqs == (0,)
    else:
        raise AssertionError("conflict must raise")

    # Broken chain never enters the compactor.
    evil = AuditSegment("evil")
    good_rec = _chain_pair(0, genesis, {"kind": "ok"})
    evil.append(good_rec)
    tampered = dict(_chain_pair(1, good_rec["chain_hash"], {"kind": "ok2"}))
    tampered["kind"] = "tampered"
    evil.append(tampered)
    try:
        AuditCompactor().add_segment(evil)
    except ChainBrokenError:
        pass
    else:
        raise AssertionError("broken chain must raise")

    print("audit-compaction OK: chains, dedup, ordering, gaps, conflicts")


if __name__ == "__main__":
    main()
