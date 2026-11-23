"""Media forensics examination ledger (image/video/audio forensic workflow).

A ``MediaForensics`` books a declared forensic workflow for media
artifacts -- examination intake, per-check findings, derived reports,
and chain-of-custody bookkeeping -- as a deterministic single-host
state machine. This module owns the *workflow* layer, deliberately
distinct from siblings:

* ``model_watermark.py`` / ``watermark_verifier.py`` -- the embed/verify
  mechanics of watermarks.
* ``provenance_attestor.py`` / ``provenance_taint.py`` -- provenance
  claims and taint propagation.
* This module -- which artifact was examined, which forensic checks ran,
  what each check found, the derived report verdict, and who held the
  artifact when.

Workflow:

1. ``examine(media_id, artifact_digest, seq, media_kind=...)`` registers
   one artifact for examination; the bytes never enter the ledger --
   only a ``sha256:<64hex>`` pin.
2. ``finding(media_id, check, verdict, seq, ...)`` books one forensic
   check result; verdicts are *data* (``authentic`` / ``manipulated`` /
   ``inconclusive`` / ``tampered``), never proof of manipulation.
   Re-running a check books a new record; history is kept.
3. ``report(media_id, seq)`` derives the report view -- pure read --
   from the latest finding per check.
4. ``chain(media_id, seq, custodian, action=...)`` books one
   chain-of-custody transfer; history is ordered and immutable.

House style: frozen dataclasses, caller-supplied int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq and book
``media-forensics.rejected``), no wall-clock, RLock-guarded,
fail-closed, stdlib-only (plus the sanctioned ``canonical_json``
try/except fallback), ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events with raw artifact bytes and check notes banned
from the audit boundary, version/schema pins, ``main()`` self-check.

Honest scope: findings are host-declared GIGO -- a booked
``manipulated`` verdict means the host declared this outcome, never that
the media is actually manipulated. Custody books declared transfers,
never proof a human really held a device. ``report`` derives a verdict
from booked data; it performs no signal analysis itself.

Version pin: media-forensics.v1
Schema pin: northstar.media-forensics.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, Tuple

try:  # pragma: no cover - repo may ship canonical_json as a module
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - stdlib fallback
    import json as _json

    def _jcs_dumps(obj) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True)

#: Module version pin.
MEDIA_FORENSICS_VERSION = "media-forensics.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.media-forensics.v1"

#: Schema pin for audit rows.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Media-kind vocabulary.
KIND_IMAGE = "image"
KIND_VIDEO = "video"
KIND_AUDIO = "audio"
KIND_DOCUMENT = "document"
_MEDIA_KINDS = frozenset({KIND_IMAGE, KIND_VIDEO, KIND_AUDIO, KIND_DOCUMENT})

#: Forensic-check vocabulary.
CHECK_METADATA = "metadata-consistency"
CHECK_COMPRESSION = "compression-artifacts"
CHECK_NOISE = "noise-analysis"
CHECK_EDGE = "edge-analysis"
CHECK_COPYMOVE = "copy-move"
CHECK_RESAMPLING = "resampling"
CHECK_WATERMARK = "watermark-presence"
CHECK_HASH = "hash-match"
_CHECKS = frozenset(
    {
        CHECK_METADATA,
        CHECK_COMPRESSION,
        CHECK_NOISE,
        CHECK_EDGE,
        CHECK_COPYMOVE,
        CHECK_RESAMPLING,
        CHECK_WATERMARK,
        CHECK_HASH,
    }
)

#: Finding verdict vocabulary (booked as data, never proof).
VERDICT_AUTHENTIC = "authentic"
VERDICT_MANIPULATED = "manipulated"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_TAMPERED = "tampered"
_VERDICTS = frozenset(
    {
        VERDICT_AUTHENTIC,
        VERDICT_MANIPULATED,
        VERDICT_INCONCLUSIVE,
        VERDICT_TAMPERED,
    }
)

#: Report verdict vocabulary.
REPORT_AUTHENTIC = "authentic"
REPORT_MANIPULATED = "manipulated"
REPORT_INCONCLUSIVE = "inconclusive"
REPORT_TAMPERED = "tampered"
REPORT_INSUFFICIENT = "insufficient-evidence"

#: Custody-action vocabulary.
ACTION_ACQUIRED = "acquired"
ACTION_TRANSFERRED = "transferred"
ACTION_ANALYZED = "analyzed"
ACTION_SEALED = "sealed"
ACTION_RELEASED = "released"
_ACTIONS = frozenset(
    {
        ACTION_ACQUIRED,
        ACTION_TRANSFERRED,
        ACTION_ANALYZED,
        ACTION_SEALED,
        ACTION_RELEASED,
    }
)

#: Audit event kinds.
KIND_EXAMINED = "media-forensics.examined"
KIND_FINDING = "media-forensics.finding"
KIND_REPORTED = "media-forensics.reported"
KIND_CUSTODY = "media-forensics.custody"
KIND_REJECTED = "media-forensics.rejected"

_KINDS = frozenset(
    {
        KIND_EXAMINED,
        KIND_FINDING,
        KIND_REPORTED,
        KIND_CUSTODY,
        KIND_REJECTED,
    }
)

#: Detail keys that must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset(
    {
        "bytes",
        "raw",
        "content",
        "payload",
        "notes",
        "note",
        "summary",
        "transcript",
        "artifact",
        "data",
        "value",
        "values",
        "image",
        "audio",
        "video",
    }
)


class MediaForensicsError(Exception):
    """Base fail-closed error for the media-forensics ledger."""


class BadMediaError(MediaForensicsError):
    """Malformed media id."""


class DuplicateMediaError(MediaForensicsError):
    """Media id already examined."""


class UnknownMediaError(MediaForensicsError):
    """Media id not known to this ledger."""


class BadDigestError(MediaForensicsError):
    """Artifact digest is not a sha256 pin."""


class BadKindError(MediaForensicsError):
    """Media kind outside the pinned vocabulary."""


class BadCheckError(MediaForensicsError):
    """Forensic check outside the pinned vocabulary."""


class BadVerdictError(MediaForensicsError):
    """Finding verdict outside the pinned vocabulary."""


class BadActionError(MediaForensicsError):
    """Custody action outside the pinned vocabulary."""


class BadCustodianError(MediaForensicsError):
    """Custodian label malformed."""


class SeqOrderError(MediaForensicsError):
    """Caller seq did not strictly increase."""


class AuditKindError(MediaForensicsError):
    """Unknown audit kind or banned detail key."""


def _check_seq(seq: object) -> int:
    """Validate a caller-supplied seq (int, non-bool, non-negative)."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_id(name: str, value: object) -> str:
    """Validate a non-empty string identifier."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadMediaError(f"{name} must be a str, got {type(value).__name__}")
    if not value or len(value) > 256:
        raise BadMediaError(f"{name} must be 1..256 chars")
    if value != value.strip():
        raise BadMediaError(f"{name} must not have surrounding whitespace")
    return value


def _check_digest(value: object) -> str:
    """Validate a sha256 digest pin (sha256:<64hex>)."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"digest must be a str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != 71:
        raise BadDigestError("digest must be 'sha256:' + 64 hex chars")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError("digest hex part is not hex") from None
    return value


def _pin(*parts: object) -> str:
    """Deterministic sha256 pin over canonical JSON of parts."""
    canonical = _jcs_dumps([str(p) for p in parts])
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def media_forensics_audit_event(kind: str, detail: Dict[str, object],
                                seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the forensics ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": MEDIA_FORENSICS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ExaminationRecord:
    """Frozen record of one media examination intake."""

    media_id: str
    media_kind: str
    artifact_digest: str
    seq: int
    digest: str

    def verify(self, media_id: str, media_kind: str,
               artifact_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("examination", media_id, media_kind,
                                   artifact_digest, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "media_id": self.media_id,
            "media_kind": self.media_kind,
            "artifact_digest": self.artifact_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class FindingRecord:
    """Frozen record of one forensic check outcome."""

    finding_id: str
    media_id: str
    check: str
    verdict: str
    confidence: int
    seq: int
    digest: str

    def verify(self, media_id: str, check: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("finding", self.finding_id, media_id,
                                   check, verdict, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "finding_id": self.finding_id,
            "media_id": self.media_id,
            "check": self.check,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CustodyRecord:
    """Frozen record of one chain-of-custody transfer."""

    custody_id: str
    media_id: str
    custodian: str
    action: str
    seq: int
    digest: str

    def verify(self, media_id: str, custodian: str, action: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("custody", self.custody_id, media_id,
                                   custodian, action, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "custody_id": self.custody_id,
            "media_id": self.media_id,
            "custodian": self.custodian,
            "action": self.action,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ForensicReport:
    """Frozen derived report -- pure read view over booked findings."""

    media_id: str
    verdict: str
    finding_ids: Tuple[str, ...]
    verdict_counts: Tuple[Tuple[str, int], ...]
    seq: int
    digest: str

    def verify(self, media_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("report", media_id, verdict, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "media_id": self.media_id,
            "verdict": self.verdict,
            "finding_ids": list(self.finding_ids),
            "verdict_counts": [list(pair) for pair in self.verdict_counts],
            "seq": self.seq,
            "digest": self.digest,
        }


class MediaForensics:
    """Deterministic media-forensics workflow ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._examinations: Dict[str, ExaminationRecord] = {}
        self._findings: Dict[str, FindingRecord] = {}
        self._by_media: Dict[str, Tuple[str, ...]] = {}
        self._custody: Dict[str, CustodyRecord] = {}
        self._custody_by_media: Dict[str, Tuple[str, ...]] = {}
        self._finding_n = 0
        self._custody_n = 0
        self._last_seq = -1
        self._audit: Tuple[Dict[str, object], ...] = ()

    # -- internals ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        """Claim a strictly increasing seq; raises bare on rewind."""
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must exceed last seq {self._last_seq}, got {seq}")
        self._last_seq = seq
        return seq

    def _burn(self, seq: int, fn) -> None:
        """Run a mutation; failed attempts consume their seq and book
        a rejected row (batch-21 claim-then-burn discipline)."""
        self._claim(seq)
        try:
            fn()
        except MediaForensicsError:
            event = media_forensics_audit_event(
                KIND_REJECTED, {"seq": seq}, seq)
            self._audit = self._audit + (event,)
            raise

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        event = media_forensics_audit_event(audit_kind, detail, seq)
        self._audit = self._audit + (event,)

    def _require_known(self, media_id: str) -> None:
        if media_id not in self._examinations:
            raise UnknownMediaError(f"unknown media id: {media_id!r}")

    # -- workflow -------------------------------------------------------

    def examine(self, media_id: str, artifact_digest: str, seq: int,
                media_kind: str = KIND_IMAGE) -> ExaminationRecord:
        """Register one artifact for forensic examination (digest-pinned)."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                _check_id("media_id", media_id)
                _check_digest(artifact_digest)
                if (isinstance(media_kind, bool)
                        or not isinstance(media_kind, str)):
                    raise BadKindError("media_kind must be a str")
                if media_kind not in _MEDIA_KINDS:
                    raise BadKindError(
                        f"media_kind must be one of {sorted(_MEDIA_KINDS)}")
                if media_id in self._examinations:
                    raise DuplicateMediaError(
                        f"media already examined: {media_id!r}")
                digest = _pin("examination", media_id, media_kind,
                              artifact_digest, seq)
                record_box.append(ExaminationRecord(
                    media_id, media_kind, artifact_digest, seq, digest))
                self._examinations[media_id] = record_box[0]
                self._by_media[media_id] = ()
                self._custody_by_media[media_id] = ()
                self._emit(KIND_EXAMINED, {"media_id": media_id}, seq)

            self._burn(seq, _do)
            return record_box[0]

    def finding(self, media_id: str, check: str, verdict: str, seq: int,
                confidence: int = 100) -> FindingRecord:
        """Book one forensic check outcome; verdicts are data, never proof."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                self._require_known(media_id)
                if isinstance(check, bool) or not isinstance(check, str):
                    raise BadCheckError("check must be a str")
                if check not in _CHECKS:
                    raise BadCheckError(
                        f"check must be one of {sorted(_CHECKS)}")
                if isinstance(verdict, bool) or not isinstance(verdict,
                                                               str):
                    raise BadVerdictError("verdict must be a str")
                if verdict not in _VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(_VERDICTS)}")
                if (isinstance(confidence, bool)
                        or not isinstance(confidence, int)):
                    raise BadVerdictError("confidence must be an int")
                if not 0 <= confidence <= 100:
                    raise BadVerdictError("confidence must be 0..100")
                self._finding_n += 1
                finding_id = f"fnd-{self._finding_n}"
                digest = _pin("finding", finding_id, media_id, check,
                              verdict, seq)
                record = FindingRecord(finding_id, media_id, check,
                                       verdict, confidence, seq, digest)
                record_box.append(record)
                self._findings[finding_id] = record
                self._by_media[media_id] = self._by_media[media_id] + (
                    finding_id,)
                self._emit(KIND_FINDING,
                           {"media_id": media_id, "finding_id": finding_id},
                           seq)

            self._burn(seq, _do)
            return record_box[0]

    def report(self, media_id: str, seq: int) -> ForensicReport:
        """Derive the report view from the latest finding per check.

        Pure read: validates seq shape, consumes nothing, writes no audit
        row. Verdict derivation is deterministic: any ``tampered`` wins,
        then ``manipulated``, then ``inconclusive``; all
        ``authentic`` yields ``authentic``; no findings at all yields
        ``insufficient-evidence`` as data.
        """
        with self._lock:
            _check_seq(seq)
            self._require_known(media_id)
            ids = self._by_media.get(media_id, ())
            latest: Dict[str, FindingRecord] = {}
            for fid in ids:
                rec = self._findings[fid]
                latest[rec.check] = rec
            verdict = REPORT_INSUFFICIENT
            if latest:
                votes = {rec.verdict for rec in latest.values()}
                if VERDICT_TAMPERED in votes:
                    verdict = REPORT_TAMPERED
                elif VERDICT_MANIPULATED in votes:
                    verdict = REPORT_MANIPULATED
                elif VERDICT_INCONCLUSIVE in votes:
                    verdict = REPORT_INCONCLUSIVE
                else:
                    verdict = REPORT_AUTHENTIC
            counts: Dict[str, int] = {}
            for rec in latest.values():
                counts[rec.verdict] = counts.get(rec.verdict, 0) + 1
            ordered = tuple(sorted(counts.items()))
            digest = _pin("report", media_id, verdict, seq)
            return ForensicReport(media_id, verdict, ids, ordered, seq,
                                  digest)

    def chain(self, media_id: str, custodian: str, seq: int,
              action: str = ACTION_TRANSFERRED) -> CustodyRecord:
        """Book one chain-of-custody transfer for an examined artifact."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                self._require_known(media_id)
                if (isinstance(custodian, bool)
                        or not isinstance(custodian, str)):
                    raise BadCustodianError("custodian must be a str")
                if not custodian or len(custodian) > 256:
                    raise BadCustodianError(
                        "custodian must be 1..256 chars")
                if isinstance(action, bool) or not isinstance(action, str):
                    raise BadActionError("action must be a str")
                if action not in _ACTIONS:
                    raise BadActionError(
                        f"action must be one of {sorted(_ACTIONS)}")
                self._custody_n += 1
                custody_id = f"cst-{self._custody_n}"
                digest = _pin("custody", custody_id, media_id, custodian,
                              action, seq)
                record = CustodyRecord(custody_id, media_id, custodian,
                                       action, seq, digest)
                record_box.append(record)
                self._custody[custody_id] = record
                self._custody_by_media[media_id] = (
                    self._custody_by_media[media_id] + (custody_id,))
                self._emit(KIND_CUSTODY,
                           {"media_id": media_id, "custody_id": custody_id},
                           seq)

            self._burn(seq, _do)
            return record_box[0]

    # -- pure views -----------------------------------------------------

    def examination(self, media_id: str, seq: int) -> ExaminationRecord:
        """Return one examination record (pure read)."""
        with self._lock:
            _check_seq(seq)
            self._require_known(media_id)
            return self._examinations[media_id]

    def findings_for(self, media_id: str, seq: int
                     ) -> Tuple[FindingRecord, ...]:
        """Return all booked findings for one artifact (pure read)."""
        with self._lock:
            _check_seq(seq)
            self._require_known(media_id)
            return tuple(self._findings[fid]
                         for fid in self._by_media.get(media_id, ()))

    def custody_for(self, media_id: str, seq: int
                    ) -> Tuple[CustodyRecord, ...]:
        """Return the chain-of-custody history for one artifact (pure
        read, oldest first)."""
        with self._lock:
            _check_seq(seq)
            self._require_known(media_id)
            return tuple(self._custody[cid]
                         for cid in self._custody_by_media.get(media_id,
                                                               ()))

    def media_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted ids of examined artifacts (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._examinations))

    def stats(self, seq: int) -> Dict[str, object]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "media": len(self._examinations),
                "findings": len(self._findings),
                "custody": len(self._custody),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """Return the audit rows booked so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return self._audit


def main() -> None:
    ledger = MediaForensics()
    digest = "sha256:" + "ab" * 32
    ledger.examine("m-1", digest, 1, KIND_IMAGE)
    ledger.finding("m-1", CHECK_METADATA, VERDICT_AUTHENTIC, 2)
    ledger.finding("m-1", CHECK_COPYMOVE, VERDICT_MANIPULATED, 3)
    ledger.chain("m-1", "lab-analyst", 4, ACTION_ACQUIRED)
    report = ledger.report("m-1", 5)
    assert report.verdict == REPORT_MANIPULATED, report.verdict
    print("media-forensics OK: examine, finding, report, chain, pins, audit")


if __name__ == "__main__":
    main()
