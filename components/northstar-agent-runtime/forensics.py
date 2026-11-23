"""DFIR evidence-acquisition ledger (digital forensics and incident response).

A ``Forensics`` books a declared digital-forensics workflow -- evidence
acquisition, declared analysis outcomes, and preservation / legal-hold --
as a deterministic single-host state machine. This module owns the
*DFIR case-lifecycle* layer, deliberately distinct from siblings:

* ``media_forensics.py`` -- media-examination workflow (examination
  intake, per-check findings, derived report, chain of custody).
* This module -- which case acquired which evidence artifact, which
  declared analyses ran against it, what each concluded, and which
  artifacts are under terminal preservation / legal-hold.

Workflow:

1. ``acquire(case_id, evidence_id, artifact_digest, seq, ...)``
   registers one evidence artifact into a case; the bytes never enter
   the ledger -- only a ``sha256:<64hex>`` pin.
2. ``analyze(evidence_id, method, conclusion, seq, ...)`` books one
   declared analysis outcome (minted ``anl-N``); conclusions are *data*
   (``attributed`` / ``compromised`` / ``clean`` / ``inconclusive`` /
   ``tampered``), never proof of a real compromise. Re-running a
   method books a new record; history is kept.
3. ``preserve(evidence_id, seq, reason=...)`` is terminal: the evidence
   enters legal-hold -- no further analyses may be booked, and the id
   is never recycled.

House style: frozen dataclasses, caller-supplied int seqs strictly
increasing (claim-then-burn: failed mutations consume their seq and book
``forensics.rejected``), no wall-clock, RLock-guarded, fail-closed,
stdlib-only (plus the sanctioned ``canonical_json`` try/except
fallback), ``sha256:`` digest pins with ``verify()``,
``audit.ndjson/1`` events with raw evidence bytes and notes banned
from the audit boundary, version/schema pins, ``main()`` self-check.

Honest scope: analyses are host-declared GIGO -- a booked
``compromised`` conclusion means the host declared this outcome, never
that a system is actually compromised. Preservation books a declared
legal-hold decision, never proof of court admissibility. This module
runs no forensic tool, images no disk, and reconstructs nothing.

Version pin: forensics.v1
Schema pin: northstar.forensics.v1
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
FORENSICS_VERSION = "forensics.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.forensics.v1"

#: Schema pin for audit rows.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Evidence-kind vocabulary.
KIND_DISK_IMAGE = "disk-image"
KIND_MEMORY_DUMP = "memory-dump"
KIND_LOG_BUNDLE = "log-bundle"
KIND_NETWORK_CAPTURE = "network-capture"
KIND_MOBILE_BACKUP = "mobile-backup"
_EVIDENCE_KINDS = frozenset(
    {
        KIND_DISK_IMAGE,
        KIND_MEMORY_DUMP,
        KIND_LOG_BUNDLE,
        KIND_NETWORK_CAPTURE,
        KIND_MOBILE_BACKUP,
    }
)

#: Analysis-method vocabulary.
METHOD_TIMELINE = "timeline-reconstruction"
METHOD_STRINGS = "string-analysis"
METHOD_HASH = "hash-correlation"
METHOD_REGISTRY = "registry-analysis"
METHOD_MALWARE = "malware-triage"
METHOD_NETFLOW = "network-flow"
_METHODS = frozenset(
    {
        METHOD_TIMELINE,
        METHOD_STRINGS,
        METHOD_HASH,
        METHOD_REGISTRY,
        METHOD_MALWARE,
        METHOD_NETFLOW,
    }
)

#: Analysis conclusion vocabulary (booked as data, never proof).
CONCLUSION_ATTRIBUTED = "attributed"
CONCLUSION_COMPROMISED = "compromised"
CONCLUSION_CLEAN = "clean"
CONCLUSION_INCONCLUSIVE = "inconclusive"
CONCLUSION_TAMPERED = "tampered"
_CONCLUSIONS = frozenset(
    {
        CONCLUSION_ATTRIBUTED,
        CONCLUSION_COMPROMISED,
        CONCLUSION_CLEAN,
        CONCLUSION_INCONCLUSIVE,
        CONCLUSION_TAMPERED,
    }
)

#: Preservation-reason vocabulary.
REASON_LEGAL_HOLD = "legal-hold"
REASON_LITIGATION = "litigation"
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_CASE_CLOSED = "case-closed"
_REASONS = frozenset(
    {
        REASON_LEGAL_HOLD,
        REASON_LITIGATION,
        REASON_MANUAL,
        REASON_SUPERSEDED,
        REASON_CASE_CLOSED,
    }
)

#: Audit event kinds.
KIND_ACQUIRED = "forensics.acquired"
KIND_ANALYZED = "forensics.analyzed"
KIND_PRESERVED = "forensics.preserved"
KIND_REJECTED = "forensics.rejected"

_KINDS = frozenset(
    {
        KIND_ACQUIRED,
        KIND_ANALYZED,
        KIND_PRESERVED,
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
        "transcript",
        "artifact",
        "data",
        "value",
        "values",
        "image",
        "disk",
        "memory",
        "logs",
        "strings",
        "evidence",
    }
)


class ForensicsError(Exception):
    """Base fail-closed error for the DFIR forensics ledger."""


class BadIdError(ForensicsError):
    """Malformed case or evidence id."""


class DuplicateEvidenceError(ForensicsError):
    """Evidence id already acquired in this ledger."""


class RetiredEvidenceError(ForensicsError):
    """Evidence id preserved -- ids are never recycled."""


class UnknownEvidenceError(ForensicsError):
    """Evidence id not known to this ledger."""


class BadDigestError(ForensicsError):
    """Artifact digest is not a sha256 pin."""


class BadKindError(ForensicsError):
    """Evidence kind outside the pinned vocabulary."""


class BadMethodError(ForensicsError):
    """Analysis method outside the pinned vocabulary."""


class BadConclusionError(ForensicsError):
    """Analysis conclusion outside the pinned vocabulary."""


class BadReasonError(ForensicsError):
    """Preservation reason outside the pinned vocabulary."""


class PreservedEvidenceError(ForensicsError):
    """Mutation attempted against preserved (legal-hold) evidence."""


class SeqOrderError(ForensicsError):
    """Caller seq did not strictly increase."""


class AuditKindError(ForensicsError):
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
        raise BadIdError(f"{name} must be a str, got {type(value).__name__}")
    if not value or len(value) > 256:
        raise BadIdError(f"{name} must be 1..256 chars")
    if value != value.strip():
        raise BadIdError(f"{name} must not have surrounding whitespace")
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


def forensics_audit_event(kind: str, detail: Dict[str, object],
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
        "module": FORENSICS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class AcquisitionRecord:
    """Frozen record of one evidence acquisition into a case."""

    case_id: str
    evidence_id: str
    evidence_kind: str
    artifact_digest: str
    seq: int
    digest: str

    def verify(self, case_id: str, evidence_id: str, evidence_kind: str,
               artifact_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("acquisition", case_id, evidence_id,
                                   evidence_kind, artifact_digest, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind,
            "artifact_digest": self.artifact_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AnalysisRecord:
    """Frozen record of one declared analysis outcome."""

    analysis_id: str
    evidence_id: str
    method: str
    conclusion: str
    confidence: int
    seq: int
    digest: str

    def verify(self, evidence_id: str, method: str,
               conclusion: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("analysis", self.analysis_id,
                                   evidence_id, method, conclusion, self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "analysis_id": self.analysis_id,
            "evidence_id": self.evidence_id,
            "method": self.method,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PreservationRecord:
    """Frozen record of terminal evidence preservation (legal-hold)."""

    evidence_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, evidence_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("preservation", evidence_id, reason,
                                   self.seq)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


class Forensics:
    """Deterministic DFIR evidence-acquisition ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._acquisitions: Dict[str, AcquisitionRecord] = {}
        self._analyses: Dict[str, AnalysisRecord] = {}
        self._by_evidence: Dict[str, Tuple[str, ...]] = {}
        self._preserved: Dict[str, PreservationRecord] = {}
        self._analysis_n = 0
        self._last_seq = -1
        self._audit: Tuple[Dict[str, object], ...] = ()

    # -- internals ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        """Claim a strictly increasing seq; raises bare on rewind."""
        _check_seq(seq)
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
        except ForensicsError:
            event = forensics_audit_event(
                KIND_REJECTED, {"seq": seq}, seq)
            self._audit = self._audit + (event,)
            raise

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        event = forensics_audit_event(audit_kind, detail, seq)
        self._audit = self._audit + (event,)

    def _require_known(self, evidence_id: str) -> None:
        if evidence_id not in self._acquisitions:
            raise UnknownEvidenceError(
                f"unknown evidence id: {evidence_id!r}")

    def _require_unpreserved(self, evidence_id: str) -> None:
        if evidence_id in self._preserved:
            raise PreservedEvidenceError(
                f"evidence is preserved (legal-hold): {evidence_id!r}")

    # -- lifecycle ------------------------------------------------------

    def acquire(self, case_id: str, evidence_id: str, artifact_digest: str,
                seq: int,
                evidence_kind: str = KIND_DISK_IMAGE) -> AcquisitionRecord:
        """Register one evidence artifact into a case (digest-pinned)."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                _check_id("case_id", case_id)
                _check_id("evidence_id", evidence_id)
                _check_digest(artifact_digest)
                if (isinstance(evidence_kind, bool)
                        or not isinstance(evidence_kind, str)):
                    raise BadKindError("evidence_kind must be a str")
                if evidence_kind not in _EVIDENCE_KINDS:
                    raise BadKindError(
                        f"evidence_kind must be one of "
                        f"{sorted(_EVIDENCE_KINDS)}")
                if evidence_id in self._preserved:
                    raise RetiredEvidenceError(
                        f"evidence id preserved -- never recycled: "
                        f"{evidence_id!r}")
                if evidence_id in self._acquisitions:
                    raise DuplicateEvidenceError(
                        f"evidence already acquired: {evidence_id!r}")
                digest = _pin("acquisition", case_id, evidence_id,
                              evidence_kind, artifact_digest, seq)
                record_box.append(AcquisitionRecord(
                    case_id, evidence_id, evidence_kind, artifact_digest,
                    seq, digest))
                self._acquisitions[evidence_id] = record_box[0]
                self._by_evidence[evidence_id] = ()
                self._emit(KIND_ACQUIRED,
                           {"case_id": case_id,
                            "evidence_id": evidence_id}, seq)

            self._burn(seq, _do)
            return record_box[0]

    def analyze(self, evidence_id: str, method: str, conclusion: str,
                seq: int, confidence: int = 100) -> AnalysisRecord:
        """Book one declared analysis outcome; conclusions are data,
        never proof."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                self._require_known(evidence_id)
                self._require_unpreserved(evidence_id)
                if isinstance(method, bool) or not isinstance(method, str):
                    raise BadMethodError("method must be a str")
                if method not in _METHODS:
                    raise BadMethodError(
                        f"method must be one of {sorted(_METHODS)}")
                if isinstance(conclusion, bool) or not isinstance(
                        conclusion, str):
                    raise BadConclusionError("conclusion must be a str")
                if conclusion not in _CONCLUSIONS:
                    raise BadConclusionError(
                        f"conclusion must be one of "
                        f"{sorted(_CONCLUSIONS)}")
                if (isinstance(confidence, bool)
                        or not isinstance(confidence, int)):
                    raise BadConclusionError("confidence must be an int")
                if not 0 <= confidence <= 100:
                    raise BadConclusionError("confidence must be 0..100")
                self._analysis_n += 1
                analysis_id = f"anl-{self._analysis_n}"
                digest = _pin("analysis", analysis_id, evidence_id,
                              method, conclusion, seq)
                record = AnalysisRecord(analysis_id, evidence_id, method,
                                        conclusion, confidence, seq, digest)
                record_box.append(record)
                self._analyses[analysis_id] = record
                self._by_evidence[evidence_id] = (
                    self._by_evidence[evidence_id] + (analysis_id,))
                self._emit(KIND_ANALYZED,
                           {"evidence_id": evidence_id,
                            "analysis_id": analysis_id}, seq)

            self._burn(seq, _do)
            return record_box[0]

    def preserve(self, evidence_id: str, seq: int,
                 reason: str = REASON_LEGAL_HOLD) -> PreservationRecord:
        """Enter terminal preservation (legal-hold) for one evidence
        artifact. Terminal: no further mutations on the evidence, and
        the id is never recycled."""
        with self._lock:
            record_box: list = []

            def _do() -> None:
                self._require_known(evidence_id)
                if evidence_id in self._preserved:
                    raise PreservedEvidenceError(
                        f"evidence already preserved: {evidence_id!r}")
                if isinstance(reason, bool) or not isinstance(reason, str):
                    raise BadReasonError("reason must be a str")
                if reason not in _REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(_REASONS)}")
                digest = _pin("preservation", evidence_id, reason, seq)
                record = PreservationRecord(evidence_id, reason, seq,
                                            digest)
                record_box.append(record)
                self._preserved[evidence_id] = record
                self._emit(KIND_PRESERVED, {"evidence_id": evidence_id},
                           seq)

            self._burn(seq, _do)
            return record_box[0]

    # -- pure views -----------------------------------------------------

    def acquisition(self, evidence_id: str, seq: int) -> AcquisitionRecord:
        """Return one acquisition record (pure read)."""
        with self._lock:
            _check_seq(seq)
            self._require_known(evidence_id)
            return self._acquisitions[evidence_id]

    def analysis(self, analysis_id: str, seq: int) -> AnalysisRecord:
        """Return one analysis record (pure read)."""
        with self._lock:
            _check_seq(seq)
            if (isinstance(analysis_id, bool)
                    or not isinstance(analysis_id, str)
                    or analysis_id not in self._analyses):
                raise UnknownEvidenceError(
                    f"unknown analysis id: {analysis_id!r}")
            return self._analyses[analysis_id]

    def analyses_for(self, evidence_id: str, seq: int
                     ) -> Tuple[AnalysisRecord, ...]:
        """Return all booked analyses for one artifact (pure read)."""
        with self._lock:
            _check_seq(seq)
            self._require_known(evidence_id)
            return tuple(self._analyses[aid]
                         for aid in self._by_evidence.get(evidence_id, ()))

    def preservation(self, evidence_id: str, seq: int
                     ) -> PreservationRecord:
        """Return the preservation record for one artifact (pure read)."""
        with self._lock:
            _check_seq(seq)
            if evidence_id not in self._preserved:
                raise UnknownEvidenceError(
                    f"evidence not preserved: {evidence_id!r}")
            return self._preserved[evidence_id]

    def case_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted ids of cases holding evidence (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(
                {rec.case_id for rec in self._acquisitions.values()}))

    def evidence_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted ids of acquired evidence artifacts (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._acquisitions))

    def preserved_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted ids of preserved evidence artifacts (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._preserved))

    def stats(self, seq: int) -> Dict[str, object]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "evidence": len(self._acquisitions),
                "analyses": len(self._analyses),
                "preserved": len(self._preserved),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        """Return the audit rows booked so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return self._audit


def main() -> None:
    ledger = Forensics()
    digest = "sha256:" + "ab" * 32
    ledger.acquire("case-1", "ev-1", digest, 1, KIND_DISK_IMAGE)
    ledger.analyze("ev-1", METHOD_TIMELINE, CONCLUSION_COMPROMISED, 2)
    ledger.analyze("ev-1", METHOD_MALWARE, CONCLUSION_INCONCLUSIVE, 3)
    ledger.preserve("ev-1", 4, REASON_LEGAL_HOLD)
    stats = ledger.stats(5)
    assert stats["evidence"] == 1, stats
    assert stats["analyses"] == 2, stats
    assert stats["preserved"] == 1, stats
    print("forensics OK: acquire, analyze, preserve, pins, audit")


if __name__ == "__main__":
    main()
