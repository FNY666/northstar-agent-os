"""GDPR: data-protection governance decision ledger, Simulated.

Research note: the EU General Data Protection Regulation (GDPR) frames
lawful personal-data processing around a small set of enforceable
decisions. Article 6 pins the lawful basis (consent, contract, legal
obligation, vital interests, public task, legitimate interests);
Article 35 requires a Data Protection Impact Assessment (DPIA) before
high-risk processing; Articles 33/34 demand breach notification to the
supervisory authority (within 72 hours of awareness) and, for
high-risk-to-rights breaches, to the affected data subjects. What
matters for this module is the *decision ledger*: which processing
activities were registered under which lawful basis, what the booked
DPIA outcome was, which remediations were declared, and which
notifications were declared - defensible bookkeeping, not proof of
compliance.

This module is the *GDPR governance decision* layer, deliberately
distinct from its siblings:

- ``consent_manager.py`` - consent lifecycle mechanics (grant /
  withdraw / check).
- ``consent_receipts.py`` - consent receipt records.
- ``differential_privacy.py`` - the differential-privacy budget ledger.
- ``compliance.py`` - generic framework -> control-check -> attestation
  governance (a GDPR framework can be registered there, but the Art.
  6/35/33/34 decision vocabulary belongs here).

This module owns the register -> assess -> remediate -> notify
lifecycle:

* **register_processing()** - declare one processing activity under a
  pinned Art. 6 lawful-basis vocabulary; activity details and data-subject
  identifiers travel as ``sha256:`` digest pins only.
* **assess()** - book one DPIA-style assessment decision (minted
  ``asm-N`` ids) over a pinned outcome vocabulary; outcomes are data,
  never proof of compliance.
* **remediate()** - book one declared remediation (minted ``rem-N``
  ids) against a non-compliant assessment; books the *declaration*,
  never the actual fix.
* **notify()** - book one declared Art. 33/34 notification decision
  (minted ``ntf-N`` ids); books the routing decision, never proof a
  notification was sent or received.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``gdpr.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module performs no DPIA, remediates no processing,
notifies no authority or data subject, and computes no legal deadlines.
A booked ``compliant`` means "the ledger says the host declared the
assessment compliant", never "the processing is lawful". Booked
``notified`` means "the ledger says a notification decision was
declared", never "a supervisory authority was actually notified within
72 hours". GIGO throughout.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
GDPR_VERSION = "gdpr.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.gdpr.v1"

#: Pinned Article 6 lawful-basis vocabulary (why processing is lawful).
LAWFUL_BASES = (
    "consent",
    "contract",
    "legal-obligation",
    "vital-interests",
    "public-task",
    "legitimate-interests",
)

#: Pinned DPIA assessment outcome vocabulary.
OUTCOMES = (
    "compliant",
    "non-compliant",
    "partial",
    "not-applicable",
)

#: Pinned residual risk-level vocabulary.
RISK_LEVELS = (
    "low",
    "medium",
    "high",
    "critical",
)

#: Pinned remediation action vocabulary.
REMEDIATION_ACTIONS = (
    "minimize-data",
    "add-safeguard",
    "restrict-purpose",
    "update-consent",
    "anonymize",
    "delete-data",
    "accept-risk",
)

#: Pinned Art. 33/34 notification channel vocabulary.
NOTIFY_CHANNELS = (
    "supervisory-authority",
    "data-subjects",
    "dpo",
    "internal",
)

#: Pinned notification reason vocabulary (why the notification was declared).
NOTIFY_REASONS = (
    "breach-72h",
    "high-risk-breach",
    "dpia-consultation",
    "manual",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "registered",
    "assessed",
    "remediated",
    "notified",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "activity",
        "activity_name",
        "activity_description",
        "description",
        "purpose",
        "subject",
        "subjects",
        "data_subject",
        "data_subjects",
        "email",
        "name",
        "breach",
        "breach_detail",
        "breach_details",
        "incident",
        "personal_data",
        "payload",
        "raw",
        "data",
        "text",
        "content",
        "note",
        "notes",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GDPRError(Exception):
    """Base error for GDPR ledger misuse."""


class BadActivityError(GDPRError):
    """Malformed processing-activity id."""


class DuplicateActivityError(GDPRError):
    """Activity id already registered."""


class UnknownActivityError(GDPRError):
    """Activity id not registered."""


class UnknownAssessmentError(GDPRError):
    """Assessment id not booked."""


class BadBasisError(GDPRError):
    """Unknown Article 6 lawful basis."""


class BadOutcomeError(GDPRError):
    """Unknown assessment outcome."""


class BadRiskError(GDPRError):
    """Unknown risk level."""


class BadActionError(GDPRError):
    """Unknown remediation action."""


class BadChannelError(GDPRError):
    """Unknown notification channel."""


class BadNotifyReasonError(GDPRError):
    """Unknown notification reason."""


class RemediationNotNeededError(GDPRError):
    """Assessment outcome needs no remediation (nothing to fix)."""


class AlreadyRemediatedError(GDPRError):
    """Assessment already has a booked remediation."""


class BadDigestError(GDPRError):
    """Malformed sha256: digest pin."""


class SeqOrderError(GDPRError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(GDPRError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadActivityError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProcessingRecord:
    activity_id: str
    lawful_basis: str
    special_category: bool
    activity_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "activity_id": self.activity_id,
            "lawful_basis": self.lawful_basis,
            "special_category": self.special_category,
            "activity_digest": self.activity_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "activity_id": self.activity_id,
                "lawful_basis": self.lawful_basis,
                "special_category": self.special_category,
                "activity_digest": self.activity_digest,
            }
        )


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    activity_id: str
    outcome: str
    risk_level: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "activity_id": self.activity_id,
            "outcome": self.outcome,
            "risk_level": self.risk_level,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "activity_id": self.activity_id,
                "outcome": self.outcome,
                "risk_level": self.risk_level,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class RemediationRecord:
    remediation_id: str
    assessment_id: str
    action: str
    plan_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "remediation_id": self.remediation_id,
            "assessment_id": self.assessment_id,
            "action": self.action,
            "plan_digest": self.plan_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "remediation_id": self.remediation_id,
                "assessment_id": self.assessment_id,
                "action": self.action,
                "plan_digest": self.plan_digest,
            }
        )


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    assessment_id: str
    channel: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "notification_id": self.notification_id,
            "assessment_id": self.assessment_id,
            "channel": self.channel,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "notification_id": self.notification_id,
                "assessment_id": self.assessment_id,
                "channel": self.channel,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class ActivityStatus:
    activity_id: str
    lawful_basis: str
    n_assessments: int
    latest_outcome: str
    n_remediations: int
    n_notifications: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "activity_id": self.activity_id,
            "lawful_basis": self.lawful_basis,
            "n_assessments": self.n_assessments,
            "latest_outcome": self.latest_outcome,
            "n_remediations": self.n_remediations,
            "n_notifications": self.n_notifications,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "activity_id": self.activity_id,
                "lawful_basis": self.lawful_basis,
                "n_assessments": self.n_assessments,
                "latest_outcome": self.latest_outcome,
                "n_remediations": self.n_remediations,
                "n_notifications": self.n_notifications,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def gdpr_audit_event(audit_kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the GDPR ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class GDPR:
    """GDPR (data-protection) governance decision ledger, Simulated.

    ``register_processing()`` / ``assess()`` / ``remediate()`` /
    ``notify()`` mutate the ledger and consume caller seqs; ``status()``
    and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._activities: Dict[str, ProcessingRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_for: Dict[str, List[str]] = {}
        self._remediations: Dict[str, RemediationRecord] = {}
        self._remediated: set = set()
        self._notifications: Dict[str, NotificationRecord] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._n_asm = 0
        self._n_rem = 0
        self._n_ntf = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = gdpr_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(gdpr_audit_event(audit_kind, seq, **details))

    # -- register_processing -------------------------------------------------

    def register_processing(
        self,
        activity_id: str,
        seq: int,
        lawful_basis: str = "consent",
        special_category: bool = False,
        activity_digest: str = "",
    ) -> ProcessingRecord:
        """Declare one processing activity under an Art. 6 lawful basis.

        Activity details and data-subject identifiers travel as
        ``sha256:`` digest pins only - raw descriptions never enter
        records.
        """
        with self._lock:
            try:
                self._claim(seq)
            except GDPRError:
                raise
            try:
                _require_id(activity_id, "activity_id")
                if lawful_basis not in LAWFUL_BASES:
                    raise BadBasisError(
                        f"lawful_basis must be one of {LAWFUL_BASES}")
                if not isinstance(special_category, bool):
                    raise BadActivityError("special_category must be a bool")
                if activity_digest:
                    _require_digest(activity_digest, "activity_digest")
                else:
                    activity_digest = "sha256:" + "00" * 32
                if activity_id in self._activities:
                    raise DuplicateActivityError(
                        f"activity already registered: {activity_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "activity_id": activity_id,
                        "lawful_basis": lawful_basis,
                        "special_category": special_category,
                        "activity_digest": activity_digest,
                    }
                )
                record = ProcessingRecord(
                    activity_id=activity_id,
                    lawful_basis=lawful_basis,
                    special_category=special_category,
                    activity_digest=activity_digest,
                    digest=digest,
                )
                self._activities[activity_id] = record
                self._assessments_for[activity_id] = []
                self._emit(
                    "registered",
                    seq,
                    activity_id=activity_id,
                    lawful_basis=lawful_basis,
                )
                return record
            except GDPRError:
                self._burn(seq, "register_processing")
                raise

    # -- assess ----------------------------------------------------------------

    def assess(
        self,
        activity_id: str,
        seq: int,
        outcome: str = "compliant",
        risk_level: str = "low",
        evidence_digest: str = "",
    ) -> AssessmentRecord:
        """Book one DPIA-style assessment decision (minted ``asm-N`` id).

        The outcome is host-declared data - never proof of compliance.
        """
        with self._lock:
            try:
                self._claim(seq)
            except GDPRError:
                raise
            try:
                _require_id(activity_id, "activity_id")
                if activity_id not in self._activities:
                    raise UnknownActivityError(
                        f"unknown activity: {activity_id!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"outcome must be one of {OUTCOMES}")
                if risk_level not in RISK_LEVELS:
                    raise BadRiskError(
                        f"risk_level must be one of {RISK_LEVELS}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = "sha256:" + "00" * 32
                self._n_asm += 1
                assessment_id = f"asm-{self._n_asm}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "assessment_id": assessment_id,
                        "activity_id": activity_id,
                        "outcome": outcome,
                        "risk_level": risk_level,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    activity_id=activity_id,
                    outcome=outcome,
                    risk_level=risk_level,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._assessments[assessment_id] = record
                self._assessments_for[activity_id].append(assessment_id)
                self._emit(
                    "assessed",
                    seq,
                    assessment_id=assessment_id,
                    activity_id=activity_id,
                    outcome=outcome,
                )
                return record
            except GDPRError:
                self._burn(seq, "assess")
                raise

    # -- remediate ---------------------------------------------------------------

    def remediate(
        self,
        assessment_id: str,
        seq: int,
        action: str = "minimize-data",
        plan_digest: str = "",
    ) -> RemediationRecord:
        """Book one declared remediation against a non-compliant assessment.

        Only failing assessments (``non-compliant`` / ``partial``) may be
        remediated; one remediation per assessment. Books the
        *declaration*, never the actual fix.
        """
        with self._lock:
            try:
                self._claim(seq)
            except GDPRError:
                raise
            try:
                if not isinstance(assessment_id, str) or not assessment_id:
                    raise UnknownAssessmentError(
                        "assessment_id must be a non-empty str")
                assessment = self._assessments.get(assessment_id)
                if assessment is None:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                if assessment.outcome not in ("non-compliant", "partial"):
                    raise RemediationNotNeededError(
                        f"assessment outcome {assessment.outcome!r} needs "
                        "no remediation")
                if assessment_id in self._remediated:
                    raise AlreadyRemediatedError(
                        f"assessment already remediated: {assessment_id!r}")
                if action not in REMEDIATION_ACTIONS:
                    raise BadActionError(
                        f"action must be one of {REMEDIATION_ACTIONS}")
                if plan_digest:
                    _require_digest(plan_digest, "plan_digest")
                else:
                    plan_digest = "sha256:" + "00" * 32
                self._n_rem += 1
                remediation_id = f"rem-{self._n_rem}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "remediation_id": remediation_id,
                        "assessment_id": assessment_id,
                        "action": action,
                        "plan_digest": plan_digest,
                    }
                )
                record = RemediationRecord(
                    remediation_id=remediation_id,
                    assessment_id=assessment_id,
                    action=action,
                    plan_digest=plan_digest,
                    digest=digest,
                )
                self._remediations[remediation_id] = record
                self._remediated.add(assessment_id)
                self._emit(
                    "remediated",
                    seq,
                    remediation_id=remediation_id,
                    assessment_id=assessment_id,
                    action=action,
                )
                return record
            except GDPRError:
                self._burn(seq, "remediate")
                raise

    # -- notify ------------------------------------------------------------------

    def notify(
        self,
        assessment_id: str,
        seq: int,
        channel: str = "supervisory-authority",
        reason: str = "manual",
    ) -> NotificationRecord:
        """Book one declared Art. 33/34 notification decision (``ntf-N``).

        Books the routing decision - never proof a notification was sent
        or received.
        """
        with self._lock:
            try:
                self._claim(seq)
            except GDPRError:
                raise
            try:
                if not isinstance(assessment_id, str) or not assessment_id:
                    raise UnknownAssessmentError(
                        "assessment_id must be a non-empty str")
                if assessment_id not in self._assessments:
                    raise UnknownAssessmentError(
                        f"unknown assessment: {assessment_id!r}")
                if channel not in NOTIFY_CHANNELS:
                    raise BadChannelError(
                        f"channel must be one of {NOTIFY_CHANNELS}")
                if reason not in NOTIFY_REASONS:
                    raise BadNotifyReasonError(
                        f"reason must be one of {NOTIFY_REASONS}")
                self._n_ntf += 1
                notification_id = f"ntf-{self._n_ntf}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "notification_id": notification_id,
                        "assessment_id": assessment_id,
                        "channel": channel,
                        "reason": reason,
                    }
                )
                record = NotificationRecord(
                    notification_id=notification_id,
                    assessment_id=assessment_id,
                    channel=channel,
                    reason=reason,
                    digest=digest,
                )
                self._notifications[notification_id] = record
                self._emit(
                    "notified",
                    seq,
                    notification_id=notification_id,
                    assessment_id=assessment_id,
                    channel=channel,
                    reason=reason,
                )
                return record
            except GDPRError:
                self._burn(seq, "notify")
                raise

    # -- status (pure read) -------------------------------------------------------

    def status(self, activity_id: str, seq: int) -> ActivityStatus:
        """Pure read: per-activity posture as data, digest-pinned."""
        with self._lock:
            self._view_seq_ok(seq)
            record = self._activities.get(activity_id)
            if record is None:
                raise UnknownActivityError(
                    f"unknown activity: {activity_id!r}")
            asm_ids = self._assessments_for.get(activity_id, [])
            integrity_ok = record.verify()
            latest_outcome = "not-assessed"
            n_remediations = 0
            n_notifications = 0
            for asm_id in asm_ids:
                asm = self._assessments[asm_id]
                if not asm.verify():
                    integrity_ok = False
                latest_outcome = asm.outcome
            for rem in self._remediations.values():
                if rem.assessment_id in self._assessments_for[activity_id]:
                    if not rem.verify():
                        integrity_ok = False
                    n_remediations += 1
            for ntf in self._notifications.values():
                if ntf.assessment_id in self._assessments_for[activity_id]:
                    if not ntf.verify():
                        integrity_ok = False
                    n_notifications += 1
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "activity_id": activity_id,
                    "lawful_basis": record.lawful_basis,
                    "n_assessments": len(asm_ids),
                    "latest_outcome": latest_outcome,
                    "n_remediations": n_remediations,
                    "n_notifications": n_notifications,
                    "integrity_ok": integrity_ok,
                }
            )
            return ActivityStatus(
                activity_id=activity_id,
                lawful_basis=record.lawful_basis,
                n_assessments=len(asm_ids),
                latest_outcome=latest_outcome,
                n_remediations=n_remediations,
                n_notifications=n_notifications,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def processing_record(self, activity_id: str, seq: int) -> ProcessingRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._activities.get(activity_id)
            if record is None:
                raise UnknownActivityError(
                    f"unknown activity: {activity_id!r}")
            return record

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return record

    def activity_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._activities))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._assessments))

    def assessments_for(self, activity_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if activity_id not in self._activities:
                raise UnknownActivityError(
                    f"unknown activity: {activity_id!r}")
            return tuple(self._assessments_for.get(activity_id, []))

    def notifications_for(self, assessment_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}")
            return tuple(
                nid for nid, ntf in self._notifications.items()
                if ntf.assessment_id == assessment_id
            )

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "activities": len(self._activities),
                "assessments": len(self._assessments),
                "remediations": len(self._remediations),
                "notifications": len(self._notifications),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    g = GDPR()
    rec = g.register_processing("act-1", 1, lawful_basis="consent")
    assert rec.verify()
    asm = g.assess("act-1", 2, outcome="non-compliant", risk_level="high")
    assert asm.verify()
    rem = g.remediate("asm-1", 3, action="minimize-data")
    assert rem.verify()
    ntf = g.notify("asm-1", 4, channel="supervisory-authority",
                   reason="breach-72h")
    assert ntf.verify()
    st = g.status("act-1", 0)
    assert st.verify()
    assert st.n_assessments == 1 and st.n_remediations == 1
    assert st.n_notifications == 1 and st.integrity_ok
    print("gdpr OK: register, assess, remediate, notify, status, pins")


if __name__ == "__main__":
    main()
