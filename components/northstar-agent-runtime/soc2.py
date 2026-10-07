"""SOC 2 trust-services assessment decision ledger: assess, attest, monitor.

Research context: SOC 2 reports (AICPA Trust Services Criteria) evaluate an
organization's controls against five trust-service *categories* --
``security`` (the mandatory common criteria), ``availability``,
``confidentiality``, ``processing-integrity``, and ``privacy``. A
``type1`` report gives an opinion on suitability of design at a point in
time; a ``type2`` report gives an opinion on operating effectiveness over a
period. Between examinations, controls are *monitored* for deficiencies.
The raw material -- control narratives, walkthrough evidence, sampling
results, auditor workpapers, deficiency details -- must never enter the
ledger or the audit trail.

This module is the *decision ledger* layer for that lifecycle. It owns the
assess -> attest -> monitor flow as a deterministic, digest-pinned state
machine with caller-int seq discipline and an audit trail. It performs no
audit procedure, inspects no controls, interviews nobody, and certifies
nothing; it books the host's *declared* decisions in a tamper-evident,
seq-ordered form.

What each operation means:

1. ``assess(assessment_id, seq, type="type2", category="security",
   scope_digest="")`` -- books one *declared* SOC 2 assessment over the
   pinned category vocabulary (``security`` / ``availability`` /
   ``confidentiality`` / ``processing-integrity`` / ``privacy``) and the
   pinned type vocabulary (``type1`` / ``type2``). Scope travels as a
   ``sha256:`` digest pin only: raw system descriptions and period dates
   never enter a record. Duplicate ids refused fail-closed.
2. ``attest(assessment_id, seq, opinion="unqualified", report_digest="")`` --
   books one *declared* SOC 2 opinion report, minted as ``att-N``. The
   opinion is pinned to ``unqualified`` / ``qualified`` / ``adverse`` /
   ``disclaimer`` and booked **as data** (a host declaration, never proof
   the opinion is warranted). The report travels as a digest pin only.
   Requires a prior assessment (fail-closed); one attestation per
   assessment.
3. ``monitor(assessment_id, seq, status="effective", control_digest="")`` --
   books one *declared* ongoing-monitoring observation, minted as
   ``mon-N``, over the pinned status vocabulary (``effective`` /
   ``deficient`` / ``significant-deficiency`` / ``material-weakness``).
   Repeatable as a monitoring chain. Requires a prior assessment
   (fail-closed).
4. ``status(assessment_id, seq)`` -- pure read view: assessment, attestation,
   and monitoring chain state plus re-derived digest integrity as data.

Distinct-layer rationale: the tree already has ``audit_management.py``
(audit-engagement plan/execute/followup), ``grc.py`` (governance workflow
ledger), ``compliance.py`` (framework control checks), ``audit_chain.py``
(tamper-evident hash chain), and ``soc.py`` (SOC operations workflow
ledger). Per the additive sibling pattern, this module is the *SOC 2
trust-services assessment* layer none of them own: category/type-shaped
assessment declarations, pinned opinion vocabulary, and the
monitor-for-deficiencies chain.

Honest scope: a booked ``unqualified`` opinion means "the host declared an
unqualified opinion at this seq", never that controls are actually
effective. A booked ``effective`` monitoring status means "the host declared
controls effective", never that monitoring actually happened. Declarations
are GIGO host claims.

House style: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn: failed mutations consume their seq and book
``soc2.rejected``; rewinds raise bare without consuming), no wall-clock,
RLock-guarded, fail-closed, stdlib-only (with the sibling
``canonical_json`` try/except fallback), ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
SOC2_VERSION = "soc2.v1"

#: Schema pin carried by records and audit events.
SOC2_SCHEMA = "northstar.soc2.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Declared SOC 2 report-type vocabulary (booked as data).
TYPES = ("type1", "type2")

#: Declared trust-service category vocabulary (booked as data).
CATEGORIES = (
    "security",
    "availability",
    "confidentiality",
    "processing-integrity",
    "privacy",
)

#: Declared opinion vocabulary (booked as data).
OPINIONS = ("unqualified", "qualified", "adverse", "disclaimer")

#: Declared monitoring-status vocabulary (booked as data).
STATUSES = (
    "effective",
    "deficient",
    "significant-deficiency",
    "material-weakness",
)

#: Audit kinds for this module (append-only vocabulary).
KIND_ASSESSED = "soc2.assessed"
KIND_ATTESTED = "soc2.attested"
KIND_MONITORED = "soc2.monitored"
KIND_REJECTED = "soc2.rejected"
_KINDS = (KIND_ASSESSED, KIND_ATTESTED, KIND_MONITORED, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class Soc2Error(Exception):
    """Base class for all SOC 2 ledger failures."""


class BadIdError(Soc2Error):
    """Assessment id is malformed."""


class DuplicateAssessmentError(Soc2Error):
    """An assessment id is already booked."""


class UnknownAssessmentError(Soc2Error):
    """No assessment is booked under this id."""


class BadTypeError(Soc2Error):
    """Report type is not in the pinned vocabulary."""


class BadCategoryError(Soc2Error):
    """Trust-service category is not in the pinned vocabulary."""


class BadOpinionError(Soc2Error):
    """Opinion is not in the pinned vocabulary."""


class BadStatusError(Soc2Error):
    """Monitoring status is not in the pinned vocabulary."""


class BadDigestError(Soc2Error):
    """A digest pin is not a valid sha256: pin (or empty)."""


class AlreadyAttestedError(Soc2Error):
    """An assessment that already has an attestation cannot be attested again."""


class NotAssessedError(Soc2Error):
    """An operation requires a prior assessment booking."""


class SeqOrderError(Soc2Error):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(Soc2Error):
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


def _check_id(value: Any, name: str = "assessment_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadIdError(f"{name} must not contain whitespace")
    return value


def _check_optional_digest(value: Any, name: str) -> str:
    """Digest pin or '' (content pins never required at assess time)."""
    if value == "":
        return ""
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    try:
        int(value[len("sha256:"):], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    return value


def _check_type(value: Any) -> str:
    if not isinstance(value, str) or value not in TYPES:
        raise BadTypeError(f"type must be one of {TYPES}")
    return value


def _check_category(value: Any) -> str:
    if not isinstance(value, str) or value not in CATEGORIES:
        raise BadCategoryError(f"category must be one of {CATEGORIES}")
    return value


def _check_opinion(value: Any) -> str:
    if not isinstance(value, str) or value not in OPINIONS:
        raise BadOpinionError(f"opinion must be one of {OPINIONS}")
    return value


def _check_status(value: Any) -> str:
    if not isinstance(value, str) or value not in STATUSES:
        raise BadStatusError(f"status must be one of {STATUSES}")
    return value


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
    h.update(b"northstar.soc2:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def soc2_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw SOC 2 material never crosses this boundary."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "report",
        "finding",
        "evidence",
        "content",
        "text",
        "payload",
        "notes",
        "scope",
        "control",
        "secret",
        "raw",
        "private",
        "deficiency",
        "transcript",
        "period",
        "workpaper",
    )
    for key in detail:
        if key in banned:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    event = {
        "schema": AUDIT_SCHEMA,
        "module": SOC2_SCHEMA,
        "kind": audit_kind,
        "seq": _check_seq(seq),
        "detail": dict(detail),
    }
    return event


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    """One booked SOC 2 assessment."""

    assessment_id: str
    type: str
    category: str
    scope_digest: str
    seq: int
    digest: str
    schema: str = SOC2_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.assessment_id,
                self.type,
                self.category,
                self.scope_digest,
                self.seq,
            ),
            "assess",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": SOC2_VERSION,
            "assessment_id": self.assessment_id,
            "type": self.type,
            "category": self.category,
            "scope_digest": self.scope_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AttestationRecord:
    """One booked SOC 2 opinion (minted att-N)."""

    attestation_id: str
    assessment_id: str
    opinion: str
    report_digest: str
    seq: int
    digest: str
    schema: str = SOC2_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.attestation_id,
                self.assessment_id,
                self.opinion,
                self.report_digest,
                self.seq,
            ),
            "attest",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": SOC2_VERSION,
            "attestation_id": self.attestation_id,
            "assessment_id": self.assessment_id,
            "opinion": self.opinion,
            "report_digest": self.report_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class MonitoringRecord:
    """One booked monitoring observation (minted mon-N)."""

    monitoring_id: str
    assessment_id: str
    status: str
    control_digest: str
    seq: int
    digest: str
    schema: str = SOC2_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.monitoring_id,
                self.assessment_id,
                self.status,
                self.control_digest,
                self.seq,
            ),
            "monitor",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": SOC2_VERSION,
            "monitoring_id": self.monitoring_id,
            "assessment_id": self.assessment_id,
            "status": self.status,
            "control_digest": self.control_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AssessmentStatus:
    """Pure read view of one assessment's lifecycle state."""

    assessment_id: str
    assessed: bool
    type: str
    category: str
    attested: bool
    opinion: str
    monitorings: int
    last_status: str
    integrity_ok: bool
    digest: str
    schema: str = SOC2_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.assessment_id,
                self.assessed,
                self.type,
                self.category,
                self.attested,
                self.opinion,
                self.monitorings,
                self.last_status,
            ),
            "status",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": SOC2_VERSION,
            "assessment_id": self.assessment_id,
            "assessed": self.assessed,
            "type": self.type,
            "category": self.category,
            "attested": self.attested,
            "opinion": self.opinion,
            "monitorings": self.monitorings,
            "last_status": self.last_status,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class SOC2:
    """SOC 2 assess -> attest -> monitor decision ledger.

    Deterministic single-host state machine: frozen records, caller-int
    seqs strictly increasing (claim-then-burn), RLock-guarded, fail-closed,
    no wall-clock, stdlib-only. Booked assessments, opinions, and monitoring
    observations are host declarations, never proof an examination was
    performed or controls are effective.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._attestations: Dict[str, AttestationRecord] = {}
        self._attestation_by_assessment: Dict[str, str] = {}
        self._monitorings: Dict[str, MonitoringRecord] = {}
        self._monitorings_by_assessment: Dict[str, List[str]] = {}
        self._n_attestation = 0
        self._n_monitoring = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ----------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(soc2_audit_event(audit_kind, seq, **detail))

    # -- mutations ----------------------------------------------------------

    def assess(
        self,
        assessment_id: Any,
        seq: Any,
        type: Any = "type2",
        category: Any = "security",
        scope_digest: Any = "",
    ) -> AssessmentRecord:
        """Book one SOC 2 assessment. Scope material travels as digest pins only."""
        with self._lock:
            seq = self._claim(seq)  # claim first: failures burn the seq
            try:
                aid = _check_id(assessment_id)
                t = _check_type(type)
                cat = _check_category(category)
                sdig = _check_optional_digest(scope_digest, "scope_digest")
                if aid in self._assessments:
                    raise DuplicateAssessmentError(f"assessment already booked: {aid!r}")
                digest = _digest_pin((aid, t, cat, sdig, seq), "assess")
                record = AssessmentRecord(
                    assessment_id=aid,
                    type=t,
                    category=cat,
                    scope_digest=sdig,
                    seq=seq,
                    digest=digest,
                )
            except Soc2Error:
                self._emit(KIND_REJECTED, seq, op="assess")
                raise
            self._assessments[aid] = record
            self._emit(
                KIND_ASSESSED,
                seq,
                assessment_id=aid,
                type=t,
                category=cat,
                scope_digest=sdig,
            )
            return record

    def attest(
        self,
        assessment_id: Any,
        seq: Any,
        opinion: Any = "unqualified",
        report_digest: Any = "",
    ) -> AttestationRecord:
        """Book one SOC 2 opinion for an assessed assessment (one-shot)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                aid = _check_id(assessment_id)
                op = _check_opinion(opinion)
                rdig = _check_optional_digest(report_digest, "report_digest")
                if aid not in self._assessments:
                    raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
                if aid in self._attestation_by_assessment:
                    raise AlreadyAttestedError(f"assessment already attested: {aid!r}")
                self._n_attestation += 1
                attid = f"att-{self._n_attestation}"
                digest = _digest_pin((attid, aid, op, rdig, seq), "attest")
                record = AttestationRecord(
                    attestation_id=attid,
                    assessment_id=aid,
                    opinion=op,
                    report_digest=rdig,
                    seq=seq,
                    digest=digest,
                )
            except Soc2Error:
                self._emit(KIND_REJECTED, seq, op="attest")
                raise
            self._attestations[attid] = record
            self._attestation_by_assessment[aid] = attid
            self._emit(
                KIND_ATTESTED,
                seq,
                attestation_id=attid,
                assessment_id=aid,
                opinion=op,
                report_digest=rdig,
            )
            return record

    def monitor(
        self,
        assessment_id: Any,
        seq: Any,
        status: Any = "effective",
        control_digest: Any = "",
    ) -> MonitoringRecord:
        """Book one monitoring observation for an assessed assessment (repeatable chain)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                aid = _check_id(assessment_id)
                st = _check_status(status)
                cdig = _check_optional_digest(control_digest, "control_digest")
                if aid not in self._assessments:
                    raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
                self._n_monitoring += 1
                mid = f"mon-{self._n_monitoring}"
                digest = _digest_pin((mid, aid, st, cdig, seq), "monitor")
                record = MonitoringRecord(
                    monitoring_id=mid,
                    assessment_id=aid,
                    status=st,
                    control_digest=cdig,
                    seq=seq,
                    digest=digest,
                )
            except Soc2Error:
                self._emit(KIND_REJECTED, seq, op="monitor")
                raise
            self._monitorings[mid] = record
            self._monitorings_by_assessment.setdefault(aid, []).append(mid)
            self._emit(
                KIND_MONITORED,
                seq,
                monitoring_id=mid,
                assessment_id=aid,
                status=st,
                control_digest=cdig,
            )
            return record

    # -- pure reads ---------------------------------------------------------

    def _read_seq(self, seq: Any) -> int:
        return _check_seq(seq)

    def assessment_record(self, assessment_id: Any, seq: Any) -> AssessmentRecord:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(assessment_id)
            if aid not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            return self._assessments[aid]

    def attestation_record(self, assessment_id: Any, seq: Any) -> AttestationRecord:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(assessment_id)
            attid = self._attestation_by_assessment.get(aid)
            if attid is None:
                raise UnknownAssessmentError(f"no attestation booked for assessment: {aid!r}")
            return self._attestations[attid]

    def monitoring_record(self, monitoring_id: Any, seq: Any) -> MonitoringRecord:
        with self._lock:
            self._read_seq(seq)
            mid = _check_id(monitoring_id, "monitoring_id")
            if mid not in self._monitorings:
                raise UnknownAssessmentError(f"unknown monitoring: {mid!r}")
            return self._monitorings[mid]

    def monitorings_for(self, assessment_id: Any, seq: Any) -> Tuple[MonitoringRecord, ...]:
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(assessment_id)
            return tuple(
                self._monitorings[mid] for mid in self._monitorings_by_assessment.get(aid, ())
            )

    def assessment_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._assessments))

    def attested_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._attestation_by_assessment))

    def pending_ids(self, seq: Any) -> Tuple[str, ...]:
        """Assessed assessments with no attestation booked yet."""
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(a for a in self._assessments if a not in self._attestation_by_assessment))

    def status(self, assessment_id: Any, seq: Any) -> AssessmentStatus:
        """Pure read view of one assessment's lifecycle state (seq never consumed)."""
        with self._lock:
            self._read_seq(seq)
            aid = _check_id(assessment_id)
            asm = self._assessments.get(aid)
            if asm is None:
                raise UnknownAssessmentError(f"unknown assessment: {aid!r}")
            attid = self._attestation_by_assessment.get(aid)
            att = self._attestations.get(attid) if attid else None
            mids = self._monitorings_by_assessment.get(aid, ())
            opinion = att.opinion if att else ""
            last_status = self._monitorings[mids[-1]].status if mids else ""
            integrity = asm.verify()
            if att is not None:
                integrity = integrity and att.verify()
            for mid in mids:
                integrity = integrity and self._monitorings[mid].verify()
            digest = _digest_pin(
                (
                    aid,
                    True,
                    asm.type,
                    asm.category,
                    att is not None,
                    opinion,
                    len(mids),
                    last_status,
                ),
                "status",
            )
            return AssessmentStatus(
                assessment_id=aid,
                assessed=True,
                type=asm.type,
                category=asm.category,
                attested=att is not None,
                opinion=opinion,
                monitorings=len(mids),
                last_status=last_status,
                integrity_ok=integrity,
                digest=digest,
            )

    def stats(self, seq: Any) -> Dict[str, Any]:
        with self._lock:
            self._read_seq(seq)
            opinion_tally: Dict[str, int] = {o: 0 for o in OPINIONS}
            for att in self._attestations.values():
                opinion_tally[att.opinion] += 1
            status_tally: Dict[str, int] = {s: 0 for s in STATUSES}
            for mon in self._monitorings.values():
                status_tally[mon.status] += 1
            type_tally: Dict[str, int] = {t: 0 for t in TYPES}
            category_tally: Dict[str, int] = {c: 0 for c in CATEGORIES}
            for asm in self._assessments.values():
                type_tally[asm.type] += 1
                category_tally[asm.category] += 1
            return {
                "schema": SOC2_SCHEMA,
                "assessed": len(self._assessments),
                "attested": len(self._attestation_by_assessment),
                "monitorings": len(self._monitorings),
                "pending": len(self._assessments) - len(self._attestation_by_assessment),
                "types": type_tally,
                "categories": category_tally,
                "opinions": opinion_tally,
                "statuses": status_tally,
                "rejected_rows": sum(1 for e in self._audit if e["kind"] == KIND_REJECTED),
            }

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(self._audit)


def main() -> None:
    ledger = SOC2()
    digest = "sha256:" + "ab" * 32
    asm = ledger.assess("s2-1", 1, type="type2", category="security", scope_digest=digest)
    assert asm.verify()
    att = ledger.attest("s2-1", 2, "unqualified", report_digest=digest)
    assert att.verify() and att.attestation_id == "att-1"
    m1 = ledger.monitor("s2-1", 3, "effective", control_digest=digest)
    assert m1.verify() and m1.monitoring_id == "mon-1"
    m2 = ledger.monitor("s2-1", 4, "deficient")
    assert m2.verify() and m2.monitoring_id == "mon-2"
    st = ledger.status("s2-1", 5)
    assert st.verify() and st.integrity_ok
    assert st.monitorings == 2 and st.last_status == "deficient"
    assert st.opinion == "unqualified"
    print("soc2 OK: assess, attest, monitor, status, pins, audit")


if __name__ == "__main__":
    main()
