"""Gramm-Leach-Bliley Act (GLBA) bookkeeping (assess / safeguard / notify).

Research note: the Gramm-Leach-Bliley Act (15 U.S.C. 6801-6809) governs
how *financial institutions* handle consumers' nonpublic personal
information (NPI). It rests on three pillars:

* **Financial Privacy Rule** (Regulation P, 12 CFR 1016) -- institutions
  must deliver initial, annual, and revised privacy notices to customers
  describing their information-sharing practices, and must give
  consumers the right to opt out of certain NPI sharing.
* **Safeguards Rule** (16 CFR 314, FTC) -- institutions must maintain a
  *written* information security program scaled to the complexity of
  their activities: designate a qualified individual, run a risk
  assessment, design safeguards (access controls, data inventory,
  encryption, secure development, MFA, testing/monitoring, secure
  disposal), oversee service providers, train personnel, monitor
  continuously, keep a written incident response plan, and report to
  the board.
* **Pretexting provisions** (15 U.S.C. 6821-6827) -- prohibit obtaining
  a customer's information by false, fictitious, or fraudulent
  statements ("pretexting").

This module books *declared* GLBA compliance decisions -- assessments,
declared safeguards, and declared privacy notices -- as a deterministic
single-host decision ledger. It enforces nothing and proves no
compliance; a booked ``compliant`` is ledger truth (host-reported),
never evidence a regulator would accept.

Public API:

* ``assess(institution_id, assessment_kind, seq, ...)`` -> frozen
  ``AssessmentRecord`` (``asm-N`` ids): books one declared assessment
  over the pinned assessment-kind and verdict vocabularies. The first
  assessment registers the institution; safeguards and notices require
  a registered institution (fail-closed).
* ``safeguard(institution_id, safeguard, seq, ...)`` -> frozen
  ``SafeguardRecord`` (``sfg-N`` ids): books one declared Safeguards
  Rule safeguard over the pinned safeguard vocabulary. Repeatable as
  a declaration chain; implementation detail travels as digest pin only.
* ``notify(institution_id, event, seq, ...)`` -> frozen
  ``NotificationRecord`` (``ntf-N`` ids): books one declared privacy
  notice or privacy event over the pinned event vocabulary. Subjects
  and notice bodies travel as digest pins only.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book ``glba.rejected``; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books declared decisions. It cannot verify an
institution's security program, cannot confirm a notice was delivered,
cannot read privacy policies, and cannot prove GLBA compliance. Raw
customer names, account numbers, SSNs, policy text, and findings never
enter records and never cross the audit boundary -- digest pins only.
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
GLBA_VERSION = "glba.v1"

#: Schema pin carried by records and audit events.
GLBA_SCHEMA = "northstar.glba.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ASSESSED = "glba.assessed"
KIND_SAFEGUARDED = "glba.safeguarded"
KIND_NOTIFIED = "glba.notified"
KIND_REJECTED = "glba.rejected"
_KINDS = frozenset(
    {
        KIND_ASSESSED,
        KIND_SAFEGUARDED,
        KIND_NOTIFIED,
        KIND_REJECTED,
    }
)

#: Pinned assessment-kind vocabulary (the three GLBA pillars + oversight).
KIND_PRIVACY_RULE = "privacy-rule"
KIND_SAFEGUARDS_RULE = "safeguards-rule"
KIND_PRETEXTING_PROTECTION = "pretexting-protection"
KIND_SERVICE_PROVIDER_OVERSIGHT = "service-provider-oversight"
_ASSESSMENT_KINDS = frozenset(
    {
        KIND_PRIVACY_RULE,
        KIND_SAFEGUARDS_RULE,
        KIND_PRETEXTING_PROTECTION,
        KIND_SERVICE_PROVIDER_OVERSIGHT,
    }
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
VERDICT_COMPLIANT = "compliant"
VERDICT_GAP_IDENTIFIED = "gap-identified"
VERDICT_NON_COMPLIANT = "non-compliant"
VERDICT_NOT_ASSESSED = "not-assessed"
_VERDICTS = frozenset(
    {
        VERDICT_COMPLIANT,
        VERDICT_GAP_IDENTIFIED,
        VERDICT_NON_COMPLIANT,
        VERDICT_NOT_ASSESSED,
    }
)

#: Verdicts that count as open gaps for posture math.
_OPEN_GAP_VERDICTS = frozenset(
    {VERDICT_GAP_IDENTIFIED, VERDICT_NON_COMPLIANT}
)

#: Pinned Safeguards Rule safeguard vocabulary (16 CFR 314.4 elements).
SAFEGUARD_DESIGNATED_COORDINATOR = "designated-coordinator"
SAFEGUARD_RISK_ASSESSMENT = "risk-assessment"
SAFEGUARD_ACCESS_CONTROLS = "access-controls"
SAFEGUARD_DATA_INVENTORY = "data-inventory"
SAFEGUARD_ENCRYPTION = "encryption"
SAFEGUARD_SECURE_DEVELOPMENT = "secure-development"
SAFEGUARD_MULTI_FACTOR_AUTH = "multi-factor-auth"
SAFEGUARD_TESTING_MONITORING = "testing-monitoring"
SAFEGUARD_PERSONNEL_TRAINING = "personnel-training"
SAFEGUARD_SERVICE_PROVIDER_OVERSIGHT = "service-provider-oversight"
SAFEGUARD_INCIDENT_RESPONSE_PLAN = "incident-response-plan"
SAFEGUARD_BOARD_REPORTING = "board-reporting"
SAFEGUARD_SECURE_DISPOSAL = "secure-disposal"
_SAFEGUARDS = frozenset(
    {
        SAFEGUARD_DESIGNATED_COORDINATOR,
        SAFEGUARD_RISK_ASSESSMENT,
        SAFEGUARD_ACCESS_CONTROLS,
        SAFEGUARD_DATA_INVENTORY,
        SAFEGUARD_ENCRYPTION,
        SAFEGUARD_SECURE_DEVELOPMENT,
        SAFEGUARD_MULTI_FACTOR_AUTH,
        SAFEGUARD_TESTING_MONITORING,
        SAFEGUARD_PERSONNEL_TRAINING,
        SAFEGUARD_SERVICE_PROVIDER_OVERSIGHT,
        SAFEGUARD_INCIDENT_RESPONSE_PLAN,
        SAFEGUARD_BOARD_REPORTING,
        SAFEGUARD_SECURE_DISPOSAL,
    }
)

#: Pinned privacy-notice/event vocabulary.
EVENT_INITIAL_PRIVACY_NOTICE = "initial-privacy-notice"
EVENT_ANNUAL_PRIVACY_NOTICE = "annual-privacy-notice"
EVENT_REVISED_PRIVACY_NOTICE = "revised-privacy-notice"
EVENT_OPT_OUT_ELECTION = "opt-out-election"
EVENT_PRETEXTING_ATTEMPT_BLOCKED = "pretexting-attempt-blocked"
EVENT_SERVICE_PROVIDER_CHANGE = "service-provider-change"
_EVENTS = frozenset(
    {
        EVENT_INITIAL_PRIVACY_NOTICE,
        EVENT_ANNUAL_PRIVACY_NOTICE,
        EVENT_REVISED_PRIVACY_NOTICE,
        EVENT_OPT_OUT_ELECTION,
        EVENT_PRETEXTING_ATTEMPT_BLOCKED,
        EVENT_SERVICE_PROVIDER_CHANGE,
    }
)

#: Raw-text keys that may never cross the audit boundary (digest pins only).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "customer",
        "consumer",
        "name",
        "ssn",
        "account",
        "policy",
        "findings",
        "notes",
        "text",
        "notice",
        "raw",
        "body",
        "detail",
        "details",
        "description",
        "payload",
        "message",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed: refuse, never guess)
# ---------------------------------------------------------------------------


class GLBAError(Exception):
    """Base class for all GLBA bookkeeping errors."""


class BadInstitutionError(GLBAError):
    """Malformed institution id."""


class UnknownInstitutionError(GLBAError):
    """No assessment is booked for this institution id."""


class BadAssessmentKindError(GLBAError):
    """Assessment kind is not in the pinned vocabulary."""


class BadVerdictError(GLBAError):
    """Assessment verdict is not in the pinned vocabulary."""


class BadSafeguardError(GLBAError):
    """Safeguard is not in the pinned vocabulary."""


class BadEventError(GLBAError):
    """Notification event is not in the pinned vocabulary."""


class BadDigestError(GLBAError):
    """A digest pin is malformed."""


class SeqOrderError(GLBAError):
    """Caller seq is not a strictly increasing int."""


class AuditKindError(GLBAError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Digest helpers (sha256: pins, type-tagged)
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:  # type: ignore[truthy-bool]
        data = _cj.jcs_dumps(obj)  # type: ignore[attr-defined]
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], tag: str) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical({"tag": tag, "parts": list(parts)})
    ).hexdigest()


def _check_digest(value: Any, name: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadDigestError(f"{name} must be a str")
    if value == "":
        if allow_empty:
            return ""
        raise BadDigestError(f"{name} must not be empty")
    if not value.startswith("sha256:") or len(value) != 7 + 64:
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{name} must be a sha256:<64hex> pin")
    return value


def _check_id(value: Any, name: str, max_len: int = 128) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise BadInstitutionError(f"{name} must be a str")
    stripped = value.strip()
    if not stripped or len(stripped) > max_len:
        raise BadInstitutionError(f"{name} must be 1..{max_len} chars")
    if any(ch.isspace() for ch in stripped):
        raise BadInstitutionError(f"{name} must not contain whitespace")
    return stripped


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be >= 0")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen; digest-pinned)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    institution_id: str
    assessment_kind: str
    verdict: str
    findings_digest: str
    assessor_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": GLBA_SCHEMA,
            "version": GLBA_VERSION,
            "assessment_id": self.assessment_id,
            "institution_id": self.institution_id,
            "assessment_kind": self.assessment_kind,
            "verdict": self.verdict,
            "findings_digest": self.findings_digest,
            "assessor_digest": self.assessor_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.assessment_id,
                self.institution_id,
                self.assessment_kind,
                self.verdict,
                self.findings_digest,
                self.assessor_digest,
                self.seq,
            ),
            "glba-assess",
        )


@dataclass(frozen=True)
class SafeguardRecord:
    safeguard_id: str
    institution_id: str
    safeguard: str
    implementation_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": GLBA_SCHEMA,
            "version": GLBA_VERSION,
            "safeguard_id": self.safeguard_id,
            "institution_id": self.institution_id,
            "safeguard": self.safeguard,
            "implementation_digest": self.implementation_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.safeguard_id,
                self.institution_id,
                self.safeguard,
                self.implementation_digest,
                self.seq,
            ),
            "glba-safeguard",
        )


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    institution_id: str
    event: str
    subject_digest: str
    notice_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": GLBA_SCHEMA,
            "version": GLBA_VERSION,
            "notification_id": self.notification_id,
            "institution_id": self.institution_id,
            "event": self.event,
            "subject_digest": self.subject_digest,
            "notice_digest": self.notice_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.notification_id,
                self.institution_id,
                self.event,
                self.subject_digest,
                self.notice_digest,
                self.seq,
            ),
            "glba-notify",
        )


@dataclass(frozen=True)
class GlbaStatus:
    institution_id: str
    assessments: int
    verdict_tallies: Tuple[Tuple[str, int], ...]
    safeguards_declared: int
    distinct_safeguards: int
    notifications: int
    open_gaps: int
    posture: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": GLBA_SCHEMA,
            "version": GLBA_VERSION,
            "institution_id": self.institution_id,
            "assessments": self.assessments,
            "verdict_tallies": [
                {"verdict": verdict, "count": count}
                for verdict, count in self.verdict_tallies
            ],
            "safeguards_declared": self.safeguards_declared,
            "distinct_safeguards": self.distinct_safeguards,
            "notifications": self.notifications,
            "open_gaps": self.open_gaps,
            "posture": self.posture,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def glba_audit_event(
    audit_kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for the GLBA ledger."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(
                f"audit detail must not carry raw-text key {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# GLBA: the GLBA compliance-decision ledger
# ---------------------------------------------------------------------------


class GLBA:
    """Bookkeeping for GLBA (Gramm-Leach-Bliley Act) decisions.

    Declared assessments, declared safeguards, and declared privacy
    notices are booked as digest-pinned decisions against pinned
    vocabularies. The ledger is a deterministic single-host state
    machine: no wall-clock, frozen records, fail-closed errors,
    ``sha256:`` digest pins, and ``audit.ndjson/1`` events for every
    transition (and every refusal).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._institutions: List[str] = []
        self._assessments: Dict[str, List[AssessmentRecord]] = {}
        self._safeguards: Dict[str, List[SafeguardRecord]] = {}
        self._notifications: Dict[str, List[NotificationRecord]] = {}
        self._assessment_counter = 0
        self._safeguard_counter = 0
        self._notification_counter = 0
        self._audit_events: List[Dict[str, Any]] = []

    # -- internals --------------------------------------------------------
    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(glba_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: GLBAError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_institution(self, institution_id: str) -> None:
        if institution_id not in self._institutions:
            raise UnknownInstitutionError(
                f"no assessment booked for {institution_id!r}"
            )

    def _register(self, institution_id: str) -> None:
        if institution_id not in self._institutions:
            self._institutions.append(institution_id)
            self._assessments[institution_id] = []
            self._safeguards[institution_id] = []
            self._notifications[institution_id] = []

    # -- mutations --------------------------------------------------------
    def assess(
        self,
        institution_id: str,
        assessment_kind: str,
        seq: int,
        verdict: str = VERDICT_NOT_ASSESSED,
        findings_digest: str = "",
        assessor_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared GLBA assessment. Repeatable; registers the
        institution on first use."""
        with self._lock:
            seq = self._claim(seq)
            try:
                institution_id = _check_id(institution_id, "institution_id")
                if assessment_kind not in _ASSESSMENT_KINDS:
                    raise BadAssessmentKindError(
                        "assessment_kind must be one of "
                        f"{sorted(_ASSESSMENT_KINDS)}"
                    )
                if verdict not in _VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(_VERDICTS)}"
                    )
                findings_digest = _check_digest(
                    findings_digest, "findings_digest", allow_empty=True
                )
                assessor_digest = _check_digest(
                    assessor_digest, "assessor_digest", allow_empty=True
                )
            except GLBAError as exc:
                self._fail(seq, exc, institution_id=str(institution_id))
            self._register(institution_id)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            record = AssessmentRecord(
                assessment_id=assessment_id,
                institution_id=institution_id,
                assessment_kind=assessment_kind,
                verdict=verdict,
                findings_digest=findings_digest,
                assessor_digest=assessor_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        assessment_id,
                        institution_id,
                        assessment_kind,
                        verdict,
                        findings_digest,
                        assessor_digest,
                        seq,
                    ),
                    "glba-assess",
                ),
            )
            self._assessments[institution_id].append(record)
            self._emit(
                KIND_ASSESSED,
                seq,
                assessment_id=assessment_id,
                institution_id=institution_id,
                assessment_kind=assessment_kind,
                verdict=verdict,
                findings_digest=findings_digest,
                assessor_digest=assessor_digest,
                record_digest=record.digest,
            )
            return record

    def safeguard(
        self,
        institution_id: str,
        safeguard: str,
        seq: int,
        implementation_digest: str = "",
    ) -> SafeguardRecord:
        """Book one declared Safeguards Rule safeguard. Repeatable as a
        declaration chain; the institution must already be registered."""
        with self._lock:
            seq = self._claim(seq)
            try:
                institution_id = _check_id(institution_id, "institution_id")
                self._require_institution(institution_id)
                if safeguard not in _SAFEGUARDS:
                    raise BadSafeguardError(
                        f"safeguard must be one of {sorted(_SAFEGUARDS)}"
                    )
                implementation_digest = _check_digest(
                    implementation_digest,
                    "implementation_digest",
                    allow_empty=True,
                )
            except GLBAError as exc:
                self._fail(seq, exc, institution_id=str(institution_id))
            self._safeguard_counter += 1
            safeguard_id = f"sfg-{self._safeguard_counter}"
            record = SafeguardRecord(
                safeguard_id=safeguard_id,
                institution_id=institution_id,
                safeguard=safeguard,
                implementation_digest=implementation_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        safeguard_id,
                        institution_id,
                        safeguard,
                        implementation_digest,
                        seq,
                    ),
                    "glba-safeguard",
                ),
            )
            self._safeguards[institution_id].append(record)
            self._emit(
                KIND_SAFEGUARDED,
                seq,
                safeguard_id=safeguard_id,
                institution_id=institution_id,
                safeguard=safeguard,
                implementation_digest=implementation_digest,
                record_digest=record.digest,
            )
            return record

    def notify(
        self,
        institution_id: str,
        event: str,
        seq: int,
        subject_digest: str = "",
        notice_digest: str = "",
    ) -> NotificationRecord:
        """Book one declared privacy notice or privacy event. Repeatable
        as an event chain; the institution must already be registered."""
        with self._lock:
            seq = self._claim(seq)
            try:
                institution_id = _check_id(institution_id, "institution_id")
                self._require_institution(institution_id)
                if event not in _EVENTS:
                    raise BadEventError(
                        f"event must be one of {sorted(_EVENTS)}"
                    )
                subject_digest = _check_digest(
                    subject_digest, "subject_digest", allow_empty=True
                )
                notice_digest = _check_digest(
                    notice_digest, "notice_digest", allow_empty=True
                )
            except GLBAError as exc:
                self._fail(seq, exc, institution_id=str(institution_id))
            self._notification_counter += 1
            notification_id = f"ntf-{self._notification_counter}"
            record = NotificationRecord(
                notification_id=notification_id,
                institution_id=institution_id,
                event=event,
                subject_digest=subject_digest,
                notice_digest=notice_digest,
                seq=seq,
                digest=_digest_pin(
                    (
                        notification_id,
                        institution_id,
                        event,
                        subject_digest,
                        notice_digest,
                        seq,
                    ),
                    "glba-notify",
                ),
            )
            self._notifications[institution_id].append(record)
            self._emit(
                KIND_NOTIFIED,
                seq,
                notification_id=notification_id,
                institution_id=institution_id,
                event=event,
                subject_digest=subject_digest,
                notice_digest=notice_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure-read views --------------------------------------------------
    def _view_seq_ok(self, seq: Any) -> None:
        _check_seq(seq)

    def assessments_for(
        self, institution_id: str, seq: int
    ) -> Tuple[AssessmentRecord, ...]:
        """Return the assessments, oldest first. Pure read."""
        self._view_seq_ok(seq)
        self._require_institution(_check_id(institution_id, "institution_id"))
        return tuple(self._assessments[institution_id])

    def safeguards_for(
        self, institution_id: str, seq: int
    ) -> Tuple[SafeguardRecord, ...]:
        """Return the declared safeguards, oldest first. Pure read."""
        self._view_seq_ok(seq)
        self._require_institution(_check_id(institution_id, "institution_id"))
        return tuple(self._safeguards[institution_id])

    def notifications_for(
        self, institution_id: str, seq: int
    ) -> Tuple[NotificationRecord, ...]:
        """Return the booked notices/events, oldest first. Pure read."""
        self._view_seq_ok(seq)
        self._require_institution(_check_id(institution_id, "institution_id"))
        return tuple(self._notifications[institution_id])

    def status(self, institution_id: str, seq: int) -> GlbaStatus:
        """Return a posture snapshot. Pure read; posture is ledger truth,
        never proof of compliance."""
        self._view_seq_ok(seq)
        institution_id = _check_id(institution_id, "institution_id")
        self._require_institution(institution_id)
        assessments = self._assessments[institution_id]
        tallies: Dict[str, int] = {v: 0 for v in sorted(_VERDICTS)}
        for record in assessments:
            tallies[record.verdict] += 1
        open_gaps = sum(
            tallies[v] for v in _OPEN_GAP_VERDICTS
        )
        safeguards = self._safeguards[institution_id]
        distinct = len({r.safeguard for r in safeguards})
        if not assessments:
            posture = "not-assessed"
        elif open_gaps:
            posture = "gaps-open"
        else:
            posture = "assessed"
        return GlbaStatus(
            institution_id=institution_id,
            assessments=len(assessments),
            verdict_tallies=tuple(
                (verdict, tallies[verdict]) for verdict in sorted(_VERDICTS)
            ),
            safeguards_declared=len(safeguards),
            distinct_safeguards=distinct,
            notifications=len(self._notifications[institution_id]),
            open_gaps=open_gaps,
            posture=posture,
        )

    def institution_ids(self, seq: int) -> Tuple[str, ...]:
        """Sorted registered institution ids. Pure read."""
        self._view_seq_ok(seq)
        return tuple(sorted(self._institutions))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters. Pure read."""
        self._view_seq_ok(seq)
        return {
            "schema": GLBA_SCHEMA,
            "version": GLBA_VERSION,
            "institutions": len(self._institutions),
            "assessments": self._assessment_counter,
            "safeguards": self._safeguard_counter,
            "notifications": self._notification_counter,
            "audit_events": len(self._audit_events),
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """The booked audit events. Pure read."""
        self._view_seq_ok(seq)
        return tuple(self._audit_events)


def main() -> None:
    ledger = GLBA()
    fin = "sha256:" + hashlib.sha256(b"findings-memo").hexdigest()
    who = "sha256:" + hashlib.sha256(b"qualified-individual").hexdigest()
    ledger.assess(
        "BANK-001",
        "safeguards-rule",
        1,
        verdict="gap-identified",
        findings_digest=fin,
        assessor_digest=who,
    )
    ledger.safeguard(
        "BANK-001",
        "encryption",
        2,
        implementation_digest=fin,
    )
    ledger.notify(
        "BANK-001",
        "annual-privacy-notice",
        3,
        subject_digest=who,
        notice_digest=fin,
    )
    status = ledger.status("BANK-001", 4)
    assert status.posture == "gaps-open"
    assert status.open_gaps == 1
    assert status.safeguards_declared == 1
    assert status.notifications == 1
    assert ledger.stats(5)["institutions"] == 1
    assert ledger.institution_ids(6) == ("BANK-001",)
    print("glba OK: assess, safeguard, notify, pins, audit")


if __name__ == "__main__":
    main()
