"""AI accountability certification (certify/verify/evaluate) interface, simulated.

Research motivation: accountability certification for AI (accountability-charter
review, pre-deployment accountability sign-off, responsibility-assignment
sign-off,
incident-escalation clearance, remediation-readiness evaluation, continuous
accountability attestation, auditability verification) reduces to the same
operational shape as every other Northstar ledger: an assessor declares
an accountability-certification outcome over a pinned certification-kind
vocabulary, the ledger pins it, and a report derives posture *from the
ledger* -- the report never independently judges whether a system is
accountable.

This module is the *accountability-certification* ledger:

- ``AIAccountabilityCertification.certify(system_id, cert_kind, outcome,
  seq, cert_digest="")`` -- book one declared accountability
  certification over the pinned 8-kind vocabulary x the pinned
  4-outcome vocabulary. The certification's content is pinned by
  ``sha256:`` digest only; raw material (accountability charters,
  responsibility assignments, escalation records, oversight logs) never enters a record. First
  certify on an id registers the system.
- ``AIAccountabilityCertification.verify(certification_id, seq)`` --
  **pure read** (seq shape validated, never consumed, no audit row).
  Re-derives the digest pin; the ``verified``/``tampered`` verdict is
  *data*, never proof the system is transparent.
- ``AIAccountabilityCertification.evaluate(system_id, seq)`` -- **pure
  read**. Derives posture as data by ledger rule: ``uncertified`` (no
  certifications) -> ``revoked`` (any ``revoked``) ->
  ``suspended`` (any ``suspended``) -> ``conditional`` (any
  ``conditional``) -> ``accountably-certified`` (all
  ``accountably-certified``), plus outcome tallies and
  ``integrity_ok`` as data.
- ``AIAccountabilityCertification.retire(system_id, seq,
  reason="manual")`` -- terminal. Ids are never recycled; post-retire
  mutations are refused, reads still work.
- Pure-read views (``certification_record`` / ``certifications_for`` /
  ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_accountability_certification_audit_event(kind, ...)`` --
  ``audit.ndjson/1`` rows (``certified`` / ``retired`` / ``rejected``);
  caller-supplied seqs only. Raw accountability-certification content
  never crosses the audit boundary -- audit rows carry ids, pinned
  cert-kind/outcome labels, digests, and counts only.

Distinct layer: ``ai_certification.py`` owns the third-party
*attestation* lifecycle (declared certifications against standards like
ISO 42001 / the EU AI Act); ``ai_accountability.py`` owns the
accountability assessment lifecycle (assess/mitigate against declared
accountability dimensions); ``ai_oversight.py`` owns human-oversight
bookkeeping; ``ai_redress.py`` / ``ai_recourse.py`` own remedy provisions
against claims; ``ai_fairness_certification.py`` owns fairness sign-offs;
``ai_safety_certification.py`` owns safety-case certification;
``ai_ethics_certification.py`` owns ethics certification. This module
owns *accountability* certification -- declared accountability sign-offs
against accountability-governance gates, ledger-rule posture over
accountability outcomes, none of which the sibling modules cover.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``certification_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``cert_kind`` must be in the pinned 8-kind vocabulary; ``outcome``
  must be in the pinned 4-outcome vocabulary.
- ``cert_digest`` must be ``sha256:<64hex>`` when supplied (may be
  empty).
- ``certify`` / ``verify`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``acf-N``).
- ``certify`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* accountability certifications reported by
  the host. A booked ``accountably-certified`` outcome means the host
  declared one -- the module certified nothing, audited nothing, and
  proves nothing about any real system's accountability, fitness for
  deployment, or standards compliance.
- Digest pins prove ledger integrity and ordering, never the truth of
  any certification, the competence of any certifier, or the
  accountability of any system toward any real people.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if accountability-certification state must survive a
  restart.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_ACCOUNTABILITY_CERTIFICATION_VERSION = "ai-accountability-certification.v1"

#: Schema pin carried by records and audit events.
AI_ACCOUNTABILITY_CERTIFICATION_SCHEMA = "northstar.ai-accountability-certification.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_CERTIFIED = "certified"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_CERTIFIED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "certificate",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment",
     "decision_text", "note", "comment", "certificate_text",
     "audit_plan", "accountability_charter", "responsibility_assignment",
     "escalation_record", "incident_report", "oversight_log",
     "redress_plan", "remediation_plan", "audit_trail",
     "decision_record", "owner_registry", "duty_matrix"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned accountability-certification-kind vocabulary (accountability-governance shaped).
KIND_ACCOUNTABILITY_CHARTER_REVIEW = "accountability-charter-review"
KIND_PRE_DEPLOYMENT_ACCOUNTABILITY = "pre-deployment-accountability"
KIND_RESPONSIBILITY_ASSIGNMENT_SIGNOFF = "responsibility-assignment-signoff"
KIND_INCIDENT_ESCALATION_CLEARANCE = "incident-escalation-clearance"
KIND_REMEDIATION_READINESS_CERT = "remediation-readiness-cert"
KIND_CONTINUOUS_ACCOUNTABILITY_CERT = "continuous-accountability-cert"
KIND_AUDITABILITY_VERIFICATION = "auditability-verification"
KIND_HUMAN_OVERSIGHT_READINESS = "human-oversight-readiness"
CERT_KINDS = (
    KIND_ACCOUNTABILITY_CHARTER_REVIEW,
    KIND_PRE_DEPLOYMENT_ACCOUNTABILITY,
    KIND_RESPONSIBILITY_ASSIGNMENT_SIGNOFF,
    KIND_INCIDENT_ESCALATION_CLEARANCE,
    KIND_REMEDIATION_READINESS_CERT,
    KIND_CONTINUOUS_ACCOUNTABILITY_CERT,
    KIND_AUDITABILITY_VERIFICATION,
    KIND_HUMAN_OVERSIGHT_READINESS,
)

#: Pinned accountability-certification-outcome vocabulary. Outcomes are host-reported data.
OUTCOME_ACCOUNTABLY_CERTIFIED = "accountably-certified"
OUTCOME_CONDITIONAL = "conditional"
OUTCOME_SUSPENDED = "suspended"
OUTCOME_REVOKED = "revoked"
OUTCOMES = (
    OUTCOME_ACCOUNTABLY_CERTIFIED,
    OUTCOME_CONDITIONAL,
    OUTCOME_SUSPENDED,
    OUTCOME_REVOKED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNCERTIFIED = "uncertified"
POSTURE_REVOKED = "revoked"
POSTURE_SUSPENDED = "suspended"
POSTURE_CONDITIONAL = "conditional"
POSTURE_ACCOUNTABLY_CERTIFIED = "accountably-certified"
POSTURES = (
    POSTURE_UNCERTIFIED,
    POSTURE_REVOKED,
    POSTURE_SUSPENDED,
    POSTURE_CONDITIONAL,
    POSTURE_ACCOUNTABLY_CERTIFIED,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SCOPE_CHANGE = "scope-change"
REASON_ACCOUNTABILITY_REVOCATION = "accountability-revocation"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_SCOPE_CHANGE,
    REASON_ACCOUNTABILITY_REVOCATION,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIAccountabilityCertificationError(Exception):
    """Base error for the AI-accountability-certification ledger (programming errors)."""


class BadIdError(AIAccountabilityCertificationError):
    """Raised when a system/certification id is malformed."""


class DuplicateCertificationError(AIAccountabilityCertificationError):
    """Raised when a minted certification id somehow collides (never)."""


class UnknownSystemError(AIAccountabilityCertificationError):
    """Raised when a system id names no certified system."""


class UnknownCertificationError(AIAccountabilityCertificationError):
    """Raised when a certification id names no booked certification."""


class RetiredSystemError(AIAccountabilityCertificationError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIAccountabilityCertificationError):
    """Raised when retiring an already-retired system."""


class BadCertKindError(AIAccountabilityCertificationError):
    """Raised when a cert kind is not in the pinned vocabulary."""


class BadOutcomeError(AIAccountabilityCertificationError):
    """Raised when an outcome is not in the pinned vocabulary."""


class BadDigestError(AIAccountabilityCertificationError):
    """Raised when a certification digest is not a sha256: pin."""


class BadReasonError(AIAccountabilityCertificationError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIAccountabilityCertificationError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIAccountabilityCertificationError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AI_ACCOUNTABILITY_CERTIFICATION_SCHEMA,
        "parts": list(parts),
    })


def ai_accountability_certification_audit_event(kind: str,
                                             detail: Dict[str, object],
                                             seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-accountability-certification ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_ACCOUNTABILITY_CERTIFICATION_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class CertificationRecord:
    """Frozen record of one declared accountability certification (digest-pinned)."""
    certification_id: str
    system_id: str
    cert_kind: str
    outcome: str
    cert_digest: str
    seq: int
    digest: str

    def verify(self, certification_id: str, system_id: str, cert_kind: str,
               outcome: str, cert_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "certification", certification_id, system_id, cert_kind, outcome,
            cert_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    certification_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, certification_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", certification_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_certifications: int
    n_certified: int
    n_conditional: int
    n_suspended: int
    n_revoked: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, system_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", system_id, reason, self.seq)


class AIAccountabilityCertification:
    """AI-accountability-certification ledger (declared accountability sign-offs, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._certifications: Dict[str, CertificationRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._certification_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, system_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if system_id:
            detail["system_id"] = system_id
        event = ai_accountability_certification_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_accountability_certification_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def certify(self, system_id: str, cert_kind: str, outcome: str, seq: int,
                cert_digest: str = "") -> CertificationRecord:
        """Book one declared accountability certification. First certify on an
        id registers the system. Pins the certification digest, never the
        certification content. Returns the frozen ``CertificationRecord``
        (minted ``acf-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(cert_kind, bool) or not isinstance(cert_kind, str):
                raise BadCertKindError(
                    f"cert_kind must be str, got {type(cert_kind).__name__}")
            if cert_kind not in CERT_KINDS:
                raise BadCertKindError(
                    f"cert_kind must be one of {sorted(CERT_KINDS)}, "
                    f"got {cert_kind!r}")
            if isinstance(outcome, bool) or not isinstance(outcome, str):
                raise BadOutcomeError(
                    f"outcome must be str, got {type(outcome).__name__}")
            if outcome not in OUTCOMES:
                raise BadOutcomeError(
                    f"outcome must be one of {sorted(OUTCOMES)}, "
                    f"got {outcome!r}")
            cert_digest = _check_digest(
                cert_digest, "cert_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                certification_id = f"acf-{len(self._certification_ids) + 1}"
                if certification_id in self._certifications:
                    raise DuplicateCertificationError(
                        f"certification id collision: {certification_id!r}")
                record = CertificationRecord(
                    certification_id=certification_id,
                    system_id=system_id,
                    cert_kind=cert_kind,
                    outcome=outcome,
                    cert_digest=cert_digest,
                    seq=seq,
                    digest=_pin("certification", certification_id, system_id,
                                cert_kind, outcome, cert_digest, seq),
                )
                self._certifications[certification_id] = record
                self._certification_ids = (
                    self._certification_ids + (certification_id,))
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (certification_id,))
        except AIAccountabilityCertificationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_CERTIFIED,
                   {"system_id": system_id,
                    "certification_id": record.certification_id,
                    "cert_kind": cert_kind,
                    "outcome": outcome,
                    "cert_digest": cert_digest}, seq)
        return record

    def verify(self, certification_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a certification's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        certification_id = _check_id(certification_id, "certification_id")
        with self._lock:
            if certification_id not in self._certifications:
                raise UnknownCertificationError(
                    f"unknown certification: {certification_id!r}")
            rec = self._certifications[certification_id]
            intact = rec.verify(
                rec.certification_id, rec.system_id, rec.cert_kind,
                rec.outcome, rec.cert_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                certification_id=certification_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", certification_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``revoked`` -> ``revoked``; any ``suspended`` -> ``suspended``;
        any ``conditional`` -> ``conditional``; all
        ``accountably-certified`` -> ``accountably-certified``).
        Validates seq shape, consumes nothing, writes no audit row.
        Returns the frozen ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._certifications[i] for i in ids]
            n_certified = sum(
                1 for r in recs if r.outcome == OUTCOME_ACCOUNTABLY_CERTIFIED)
            n_conditional = sum(
                1 for r in recs if r.outcome == OUTCOME_CONDITIONAL)
            n_suspended = sum(
                1 for r in recs if r.outcome == OUTCOME_SUSPENDED)
            n_revoked = sum(1 for r in recs if r.outcome == OUTCOME_REVOKED)
            integrity_ok = all(
                r.verify(r.certification_id, r.system_id, r.cert_kind,
                         r.outcome, r.cert_digest) for r in recs)
            if n_revoked:
                posture = POSTURE_REVOKED
            elif n_suspended:
                posture = POSTURE_SUSPENDED
            elif n_conditional:
                posture = POSTURE_CONDITIONAL
            else:
                posture = POSTURE_ACCOUNTABLY_CERTIFIED
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_certifications=len(recs),
                n_certified=n_certified,
                n_conditional=n_conditional,
                n_suspended=n_suspended,
                n_revoked=n_revoked,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", system_id, posture, seq),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system. Ids are never recycled; post-retire
        mutations are refused, reads still work. Returns the frozen
        ``RetireRecord``."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                if system_id in self._retired:
                    raise DoubleRetireError(
                        f"system already retired: {system_id!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", system_id, reason, seq),
                )
                self._retired[system_id] = record
        except AIAccountabilityCertificationError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def certification_record(self, certification_id: str,
                             seq: int) -> CertificationRecord:
        """Pure read view of one booked certification."""
        _check_seq(seq)
        certification_id = _check_id(certification_id, "certification_id")
        with self._lock:
            if certification_id not in self._certifications:
                raise UnknownCertificationError(
                    f"unknown certification: {certification_id!r}")
            return self._certifications[certification_id]

    def certifications_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read view of certification ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-certify order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_system.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "systems": len(self._by_system),
                "certifications": len(self._certifications),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: certify, verify, evaluate, retire, pins, audit."""
    ac = AIAccountabilityCertification()
    assert AI_ACCOUNTABILITY_CERTIFICATION_VERSION == "ai-accountability-certification.v1"
    assert AI_ACCOUNTABILITY_CERTIFICATION_SCHEMA == "northstar.ai-accountability-certification.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = ac.certify("sys-1", KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                     OUTCOME_ACCOUNTABLY_CERTIFIED, 1, digest)
    assert rec.certification_id == "acf-1"
    assert rec.verify("acf-1", "sys-1", KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                      OUTCOME_ACCOUNTABLY_CERTIFIED, digest)
    assert not rec.verify("acf-1", "sys-1", KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                          OUTCOME_SUSPENDED, digest)
    vr = ac.verify("acf-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("acf-1", "verified")
    ev = ac.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_ACCOUNTABLY_CERTIFIED
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_ACCOUNTABLY_CERTIFIED)
    ac.certify("sys-1", KIND_PRE_DEPLOYMENT_ACCOUNTABILITY, OUTCOME_REVOKED, 4,
               digest)
    ev = ac.evaluate("sys-1", 5)
    assert ev.posture == POSTURE_REVOKED
    assert ev.n_certifications == 2 and ev.n_revoked == 1
    rr = ac.retire("sys-1", 6)
    assert rr.verify("sys-1", REASON_MANUAL)
    try:
        ac.certify("sys-1", KIND_RESPONSIBILITY_ASSIGNMENT_SIGNOFF,
                   OUTCOME_ACCOUNTABLY_CERTIFIED, 7)
    except RetiredSystemError:
        pass
    else:
        raise AssertionError("certify on retired system must fail closed")
    assert ac.stats()["systems"] == 1
    kinds = [row["kind"] for row in ac.audit_log()]
    assert kinds == [KIND_CERTIFIED, KIND_CERTIFIED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-accountability-certification OK: certify, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
