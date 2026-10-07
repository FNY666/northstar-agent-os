"""Backdoor detection decision ledger: scan, quarantine, report.

Research context: neural backdoors (BadNet, TrojanNN, sleeper agents) embed a
*trigger* in a model that switches on malicious behavior when the trigger
appears in the input. The dangerous direction is model *inspection*
(activation clustering, trigger inversion, weight-diff analysis) plus the
containment *decision* when something is found.

This module is the *decision ledger* layer for that workflow. It is
deliberately distinct from the sibling ``backdoor_detector.py`` (the
runtime text-level trigger-shape scanner with module-level functions):
this module owns the scan → quarantine → report lifecycle as a
deterministic, digest-pinned state machine with caller-int seq discipline
and an audit trail.

What each operation means:

1. ``scan(scan_id, artifact_digest, seq, ...)`` -- books one *declared*
   backdoor scan of a digest-pinned artifact (model weights, prompt pack,
   dataset shard). The verdict (``clean`` / ``suspicious`` / ``backdoored``)
   is **host-declared and booked as data**, never proof of a backdoor.
   The module runs no inspection, sees no weights, and proves nothing
   about the artifact; it only books the host's declaration in a
   tamper-evident, seq-ordered form.
2. ``quarantine(scan_id, seq, reason=...)`` -- books a terminal containment
   decision against a scan with a non-clean verdict. A quarantined scan id
   can never be re-scanned, re-quarantined, or recycled.
3. ``report(scan_id, seq)`` -- pure read view: the scan's declared verdict,
   its quarantine state, and a re-derivation of every digest pin as data.

Honest scope: a booked ``backdoored`` verdict means "the host declared this
artifact backdoored at this seq", never "this artifact contains a backdoor".
A quarantined id means "the ledger says containment was ordered", never that
the artifact is actually isolated. Verdicts are GIGO host declarations.

House style: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn: failed mutations consume their seq and book
``backdoor-detection.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed, stdlib-only (with the sibling
``canonical_json`` try/except fallback), ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
BACKDOOR_DETECTION_VERSION = "backdoor-detection.v1"

#: Schema pin carried by records and audit events.
BACKDOOR_DETECTION_SCHEMA = "northstar.backdoor-detection.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Kinds of artifact a scan may cover (pinned vocabulary).
ARTIFACT_KINDS = ("model", "prompt-pack", "dataset", "adapter")

#: Declared inspection methods (pinned vocabulary -- books the host's claim
#: about which method produced the verdict, not the method's execution).
METHODS = (
    "activation-clustering",
    "trigger-inversion",
    "weight-diff",
    "fine-tuning-probe",
    "behavioral-redteam",
    "human-review",
)

#: Declared verdict vocabulary (booked as data).
VERDICTS = ("clean", "suspicious", "backdoored")

#: Quarantine reason vocabulary.
REASONS = ("manual", "trigger-confirmed", "policy", "precaution", "duplicate")

#: Audit kinds for this module (append-only vocabulary).
KIND_SCANNED = "backdoor-detection.scanned"
KIND_QUARANTINED = "backdoor-detection.quarantined"
KIND_REJECTED = "backdoor-detection.rejected"
_KINDS = (KIND_SCANNED, KIND_QUARANTINED, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class BackdoorDetectionError(Exception):
    """Base class for all backdoor-detection ledger failures."""


class BadIdError(BackdoorDetectionError):
    """Scan id is malformed."""


class DuplicateScanError(BackdoorDetectionError):
    """A scan id is already booked."""


class RetiredScanError(BackdoorDetectionError):
    """A quarantined scan id can never be reused."""


class UnknownScanError(BackdoorDetectionError):
    """No scan is booked under this id."""


class BadDigestError(BackdoorDetectionError):
    """Artifact digest is not a sha256: pin."""


class BadKindError(BackdoorDetectionError):
    """Artifact kind is not in the pinned vocabulary."""


class BadMethodError(BackdoorDetectionError):
    """Inspection method is not in the pinned vocabulary."""


class BadVerdictError(BackdoorDetectionError):
    """Verdict is not in the pinned vocabulary."""


class BadConfidenceError(BackdoorDetectionError):
    """Confidence is not a finite [0, 100] number (bools refused)."""


class BadReasonError(BackdoorDetectionError):
    """Quarantine reason is not in the pinned vocabulary."""


class DoubleQuarantineError(BackdoorDetectionError):
    """A scan that is already quarantined cannot be quarantined again."""


class CleanQuarantineError(BackdoorDetectionError):
    """A scan with a declared-clean verdict cannot be quarantined."""


class SeqOrderError(BackdoorDetectionError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(BackdoorDetectionError):
    """Unknown audit kind or banned key in audit detail."""


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str = "scan_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadIdError(f"{name} must not contain whitespace")
    return value


def _check_digest(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise BadDigestError("digest must be a 'sha256:<64hex>' pin")
    try:
        int(value[len("sha256:"):], 16)
    except ValueError:
        raise BadDigestError("digest must be a 'sha256:<64hex>' pin")
    return value


def _check_confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadConfidenceError("confidence must be a number in [0, 100]")
    f = float(value)
    if f != f or f == float("inf") or f == float("-inf"):
        raise BadConfidenceError("confidence must be finite")
    if not 0.0 <= f <= 100.0:
        raise BadConfidenceError("confidence must be in [0, 100]")
    return f


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        try:
            return _cj.jcs_dumps(obj).encode("utf-8")
        except Exception:
            pass
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.backdoor-detection:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def backdoor_detection_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw content never crosses this boundary."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "weights",
        "weight",
        "model",
        "artifact",
        "content",
        "text",
        "raw",
        "payload",
        "prompt",
        "prompts",
        "trigger",
        "triggers",
        "input",
        "inputs",
        "data",
        "secret",
        "secrets",
        "key",
        "keys",
        "bytes",
        "note",
        "notes",
        "reason",
        "comment",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "backdoor_detection",
        "kind": audit_kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((audit_kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanRecord:
    """One declared backdoor scan, booked at a claimed seq."""

    scan_id: str
    artifact_digest: str
    artifact_kind: str
    method: str
    verdict: str
    confidence: float
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.scan_id,
                self.artifact_digest,
                self.artifact_kind,
                self.method,
                self.verdict,
                self.confidence,
                self.seq,
            ),
            "scan",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": BACKDOOR_DETECTION_SCHEMA,
            "scan_id": self.scan_id,
            "artifact_digest": self.artifact_digest,
            "artifact_kind": self.artifact_kind,
            "method": self.method,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class QuarantineRecord:
    """One declared containment decision against a scan."""

    scan_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.scan_id, self.reason, self.seq), "quarantine")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": BACKDOOR_DETECTION_SCHEMA,
            "scan_id": self.scan_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class DetectionReport:
    """Pure read view: declared verdict + quarantine state + pin re-derivation."""

    scan_id: str
    verdict: str
    quarantined: bool
    integrity_ok: bool
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": BACKDOOR_DETECTION_SCHEMA,
            "scan_id": self.scan_id,
            "verdict": self.verdict,
            "quarantined": self.quarantined,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class BackdoorDetection:
    """Backdoor detection decision ledger: scan, quarantine, report.

    ``scan()`` and ``quarantine()`` are mutations under claim-then-burn seq
    discipline; ``report()`` and the other views are pure reads (seq shape
    validated, never consumed, no audit rows).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # scan_id -> ScanRecord (booking order)
        self._scans: Dict[str, ScanRecord] = {}
        # scan_id -> QuarantineRecord
        self._quarantines: Dict[str, QuarantineRecord] = {}
        # quarantined scan ids (never recycled)
        self._retired: set = set()
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(backdoor_detection_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, error: BackdoorDetectionError, **detail: Any) -> None:
        """Book a rejected row for a failed mutation, then raise."""
        detail = dict(detail)
        detail["error"] = type(error).__name__
        self._emit(KIND_REJECTED, seq, **detail)
        raise error

    # -- mutations ---------------------------------------------------------

    def scan(
        self,
        scan_id: str,
        artifact_digest: str,
        seq: int,
        artifact_kind: str = "model",
        method: str = "activation-clustering",
        verdict: str = "clean",
        confidence: float = 100.0,
    ) -> ScanRecord:
        """Book one declared backdoor scan.

        The artifact travels as a digest pin only; the verdict is the host's
        declaration, booked as data. Duplicate ids and quarantined (retired)
        ids are refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                scan_id = _check_id(scan_id)
                if scan_id in self._retired:
                    raise RetiredScanError(f"scan id retired by quarantine: {scan_id!r}")
                if scan_id in self._scans:
                    raise DuplicateScanError(f"scan already booked: {scan_id!r}")
                artifact_digest = _check_digest(artifact_digest)
                if not isinstance(artifact_kind, str) or artifact_kind not in ARTIFACT_KINDS:
                    raise BadKindError(f"artifact_kind must be one of {ARTIFACT_KINDS}")
                if not isinstance(method, str) or method not in METHODS:
                    raise BadMethodError(f"method must be one of {METHODS}")
                if not isinstance(verdict, str) or verdict not in VERDICTS:
                    raise BadVerdictError(f"verdict must be one of {VERDICTS}")
                confidence = _check_confidence(confidence)
            except BackdoorDetectionError as e:
                self._fail(seq, e, scan_id=str(scan_id)[:64])
            digest = _digest_pin(
                (scan_id, artifact_digest, artifact_kind, method, verdict, confidence, seq),
                "scan",
            )
            record = ScanRecord(
                scan_id=scan_id,
                artifact_digest=artifact_digest,
                artifact_kind=artifact_kind,
                method=method,
                verdict=verdict,
                confidence=confidence,
                seq=seq,
                digest=digest,
            )
            self._scans[scan_id] = record
            self._emit(
                KIND_SCANNED,
                seq,
                scan_id=scan_id,
                artifact_kind=artifact_kind,
                method=method,
                verdict=verdict,
                confidence=confidence,
            )
            return record

    def quarantine(self, scan_id: str, seq: int, reason: str = "manual") -> QuarantineRecord:
        """Book a terminal containment decision against a scan.

        Refused fail-closed for unknown scans, already-quarantined scans,
        and scans whose declared verdict is clean.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                scan_id = _check_id(scan_id)
                if scan_id not in self._scans:
                    raise UnknownScanError(f"no scan booked: {scan_id!r}")
                if scan_id in self._quarantines:
                    raise DoubleQuarantineError(f"scan already quarantined: {scan_id!r}")
                if not isinstance(reason, str) or reason not in REASONS:
                    raise BadReasonError(f"reason must be one of {REASONS}")
                if self._scans[scan_id].verdict == "clean":
                    raise CleanQuarantineError(
                        f"cannot quarantine a clean-verdict scan: {scan_id!r}"
                    )
            except BackdoorDetectionError as e:
                self._fail(seq, e, scan_id=str(scan_id)[:64])
            digest = _digest_pin((scan_id, reason, seq), "quarantine")
            record = QuarantineRecord(scan_id=scan_id, reason=reason, seq=seq, digest=digest)
            self._quarantines[scan_id] = record
            self._retired.add(scan_id)
            self._emit(KIND_QUARANTINED, seq, scan_id=scan_id, quarantine_reason=reason)
            return record

    # -- pure reads ----------------------------------------------------------

    def report(self, scan_id: str, seq: int) -> DetectionReport:
        """Pure read: verdict + quarantine state + pin re-derivation as data.

        Seq is shape-validated but never consumed; no audit row is written.
        """
        _check_seq(seq)
        with self._lock:
            if not isinstance(scan_id, str):
                raise BadIdError("scan_id must be a non-empty str")
            scan = self._scans.get(scan_id)
            if scan is None:
                raise UnknownScanError(f"no scan booked: {scan_id!r}")
            quarantined = scan_id in self._quarantines
            integrity_ok = scan.verify()
            if quarantined:
                integrity_ok = integrity_ok and self._quarantines[scan_id].verify()
            return DetectionReport(
                scan_id=scan_id,
                verdict=scan.verdict,
                quarantined=quarantined,
                integrity_ok=integrity_ok,
                seq=seq,
            )

    def scan_record(self, scan_id: str, seq: int) -> ScanRecord:
        _check_seq(seq)
        with self._lock:
            record = self._scans.get(scan_id)
            if record is None:
                raise UnknownScanError(f"no scan booked: {scan_id!r}")
            return record

    def quarantine_record(self, scan_id: str, seq: int) -> QuarantineRecord:
        _check_seq(seq)
        with self._lock:
            record = self._quarantines.get(scan_id)
            if record is None:
                raise UnknownScanError(f"no quarantine booked: {scan_id!r}")
            return record

    def scan_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(self._scans)

    def quarantined_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(self._quarantines)

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        with self._lock:
            verdicts: Dict[str, int] = {v: 0 for v in VERDICTS}
            for record in self._scans.values():
                verdicts[record.verdict] += 1
            return {
                "scans": len(self._scans),
                "quarantined": len(self._quarantines),
                "by_verdict": verdicts,
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    ledger = BackdoorDetection()
    digest = "sha256:" + "ab" * 32
    record = ledger.scan("scn-1", digest, 1, verdict="backdoored", confidence=92.5)
    assert record.verify()
    ledger.quarantine("scn-1", 2, reason="trigger-confirmed")
    report = ledger.report("scn-1", 3)
    assert report.quarantined and report.integrity_ok
    assert report.verdict == "backdoored"
    print("backdoor-detection OK: scan, quarantine, report, pins, audit")


if __name__ == "__main__":
    main()
