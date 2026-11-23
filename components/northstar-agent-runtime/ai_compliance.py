"""AI compliance: AI-compliance-assessment decision ledger, Simulated.

Research note: AI compliance is the conformance side of AI governance -
after an AI system is deployed (model, agent, tool, pipeline), which
compliance domain the host declared it assessed (regulatory compliance,
data governance, safety standards, ethical guidelines, audit readiness,
risk management, disclosure obligations, incident reporting), what
verdict it declared against that domain, and what compliance posture
the ledger derives for the system. This module is the *decision
ledger* for declared AI compliance assessments: which systems had
which compliance kinds booked (over a pinned compliance-kind
vocabulary), what verdicts were declared against them, and what
compliance posture the ledger derives - defensible bookkeeping, never
proof that any system is really compliant.

This module owns the assess -> verify -> evaluate lifecycle:

* **assess()** - book one declared compliance assessment (minted
  ``asm-N`` ids; pinned compliance-kind vocabulary over the common
  compliance domains; pinned verdict vocabulary booked *as data*); the
  first assessment on an id registers the system; raw audit evidence,
  compliance reports, remediation plans, policy text, legal advice, and
  findings never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one assessment record's
  digest pin; verdict ``verified`` / ``tampered`` booked as data, never
  as proof the assessment really happened.
* **evaluate()** - **pure read**: derive one system's compliance
  posture as data (``unassessed`` -> ``non-compliant`` -> ``contested``
  -> ``partially-compliant`` -> ``compliant``) with verdict tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``compliance.py`` owns general
compliance mechanics, ``compliance_checker.py`` owns check execution,
``compliance_reports.py`` owns report generation, ``step_compliance.py``
owns step-level compliance checks; ``ai_regulation.py`` owns regulatory
assessment -> enforcement, ``ai_act.py`` owns AI-Act-specific
conformance bookkeeping, ``ai_charter.py`` / ``ai_constitution.py``
own charter/constitution assessment lifecycles, ``ai_assurance.py``
owns assurance-statement bookkeeping, ``ai_certification.py`` owns
certification-record bookkeeping - this module is the *AI-compliance
assessment* ledger none of them own: declared compliance assessments
over a pinned compliance-domain vocabulary, host-reported severity,
declared digest pins, digest re-derivation, and the ledger-rule posture
that turns declared assessments into a compliance claim, always as
data, never as measured conformity.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-compliance.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module assesses nothing, certifies nothing,
audits nothing, and proves nothing about real-world conformity. A
booked ``compliant`` posture means "the host declared it", never "the
system is compliant"; a booked ``non-compliant`` verdict means "the
host declared it", never "the system truly violates". Audit evidence,
compliance reports, remediation plans, policy text, regulation text,
legal advice, findings, and raw assessment artifacts never enter
records or cross the audit boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
AI_COMPLIANCE_VERSION = "ai-compliance.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-compliance.v1"

#: Pinned compliance-kind vocabulary (the compliance domains).
COMPLIANCE_KINDS = (
    "regulatory-compliance",
    "data-governance",
    "safety-standards",
    "ethical-guidelines",
    "audit-readiness",
    "risk-management",
    "disclosure-obligations",
    "incident-reporting",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
ASSESSMENT_VERDICTS = (
    "compliant",
    "partially-compliant",
    "non-compliant",
    "inconclusive",
    "not-assessed",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unassessed",
    "non-compliant",
    "contested",
    "partially-compliant",
    "compliant",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "audit_evidence",
        "evidence_package",
        "evidence_items",
        "compliance_report",
        "compliance_reports",
        "remediation_plan",
        "remediation_plans",
        "policy_text",
        "policy_texts",
        "regulation_text",
        "regulation_texts",
        "legal_advice",
        "legal_opinion",
        "findings_report",
        "findings",
        "audit_finding",
        "audit_findings",
        "assessor_notes",
        "assessor_identity",
        "gap_analysis",
        "corrective_action",
        "corrective_actions",
        "enforcement_notice",
        "questionnaire",
        "questionnaires",
        "control_evidence",
        "control_evidence_items",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "checkpoint_data",
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "stderr",
        "stdout",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "report",
        "reports",
        "incident_text",
        "incident_detail",
        "incident_description",
        "postmortem",
        "root_cause",
        "harm",
        "harm_description",
        "damage",
        "damages",
        "remedy_text",
        "password",
        "passwords",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "api_key",
        "api_keys",
        "token",
        "tokens",
        "private_key",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "dataset",
        "datasets",
        "training_data",
        "pii",
        "exploit",
        "exploits",
        "payload",
        "vulnerability_detail",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIComplianceError(Exception):
    """Base class for all ai-compliance ledger errors."""


class BadSystemError(AIComplianceError):
    pass


class UnknownSystemError(AIComplianceError):
    pass


class RetiredSystemError(AIComplianceError):
    pass


class BadComplianceKindError(AIComplianceError):
    pass


class BadVerdictError(AIComplianceError):
    pass


class BadSeverityError(AIComplianceError):
    pass


class BadDigestError(AIComplianceError):
    pass


class BadReasonError(AIComplianceError):
    pass


class UnknownAssessmentError(AIComplianceError):
    pass


class SeqOrderError(AIComplianceError):
    pass


class AuditKindError(AIComplianceError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_compliance_kind(value: Any) -> str:
    if value not in COMPLIANCE_KINDS:
        raise BadComplianceKindError(f"compliance_kind must be one of {COMPLIANCE_KINDS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in ASSESSMENT_VERDICTS:
        raise BadVerdictError(f"verdict must be one of {ASSESSMENT_VERDICTS}")
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if value < 0 or value > 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    compliance_kind: str
    verdict: str
    severity: int
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assess_payload(self), "ai-compliance.assess"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(_retire_payload(self), "ai-compliance.retire")


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-compliance.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_compliant: int
    n_partial: int
    n_noncompliant: int
    n_inconclusive: int
    n_not_assessed: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-compliance.evaluate"
        )


def _assess_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "compliance_kind": rec.compliance_kind,
        "verdict": rec.verdict,
        "severity": rec.severity,
        "assessment_digest": rec.assessment_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_assessments": rep.n_assessments,
        "n_compliant": rep.n_compliant,
        "n_partial": rep.n_partial,
        "n_noncompliant": rep.n_noncompliant,
        "n_inconclusive": rep.n_inconclusive,
        "n_not_assessed": rep.n_not_assessed,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_compliance_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in EMIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AIComplianceError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-compliance",
        "version": AI_COMPLIANCE_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AICompliance:
    """AI-compliance assessment decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that any system is really compliant.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_compliance_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-compliance",
                "version": AI_COMPLIANCE_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_compliance_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        compliance_kind: str = "regulatory-compliance",
        verdict: str = "not-assessed",
        severity: int = 0,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared compliance assessment (minted ``asm-N`` id).

        The first assessment on an id registers the system. Raw audit
        evidence, compliance reports, remediation plans, policy text,
        legal advice, and findings never enter records - digest pins
        only. Fail-closed: failed mutations consume their seq and book
        an ``ai-compliance.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                compliance_kind = _check_compliance_kind(compliance_kind)
                verdict = _check_verdict(verdict)
                severity = _check_severity(severity)
                assessment_digest = _check_digest(assessment_digest, "assessment_digest")
                self._require_live(system_id)
            except AIComplianceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                compliance_kind=compliance_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assess_payload(provisional), "ai-compliance.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                compliance_kind=compliance_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = rec
            self._system_assessments.setdefault(system_id, []).append(assessment_id)
            self._emit(
                "assessed",
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                compliance_kind=compliance_kind,
                verdict=verdict,
                severity=severity,
                assessment_digest=assessment_digest,
            )
            return rec

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id in self._retired:
                    raise RetiredSystemError(f"system is retired: {system_id!r}")
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
            except AIComplianceError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(_retire_payload(provisional), "ai-compliance.retire")
            rec = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assessment record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the assessment really happened. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(record_id, bool)
                or not isinstance(record_id, str)
                or record_id not in self._assessments
            ):
                raise UnknownAssessmentError(f"unknown assessment id: {record_id!r}")
            rec = self._assessments[record_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_verify_payload(provisional), "ai-compliance.verify")
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's compliance posture as data.

        Posture by ledger rule: ``unassessed`` (nothing booked) ->
        ``non-compliant`` (any non-compliant) -> ``contested`` (any
        inconclusive) -> ``partially-compliant`` (any
        partially-compliant) -> ``compliant`` (all compliant).
        ``integrity_ok`` re-derives all in-scope digest pins as data.
        Seq is shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            if system_id not in self._system_assessments:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            ids = self._system_assessments[system_id]
            recs = [self._assessments[i] for i in ids]
            n_compliant = sum(1 for r in recs if r.verdict == "compliant")
            n_partial = sum(1 for r in recs if r.verdict == "partially-compliant")
            n_noncompliant = sum(1 for r in recs if r.verdict == "non-compliant")
            n_inconclusive = sum(1 for r in recs if r.verdict == "inconclusive")
            n_not_assessed = sum(1 for r in recs if r.verdict == "not-assessed")
            if n_noncompliant:
                posture = "non-compliant"
            elif n_inconclusive:
                posture = "contested"
            elif n_partial:
                posture = "partially-compliant"
            elif n_compliant and n_compliant == len(recs):
                posture = "compliant"
            else:
                posture = "unassessed"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(recs),
                n_compliant=n_compliant,
                n_partial=n_partial,
                n_noncompliant=n_noncompliant,
                n_inconclusive=n_inconclusive,
                n_not_assessed=n_not_assessed,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(_evaluate_payload(provisional), "ai-compliance.evaluate")
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(recs),
                n_compliant=n_compliant,
                n_partial=n_partial,
                n_noncompliant=n_noncompliant,
                n_inconclusive=n_inconclusive,
                n_not_assessed=n_not_assessed,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._check_read_seq(seq)
            if assessment_id not in self._assessments:
                raise UnknownAssessmentError(f"unknown assessment id: {assessment_id!r}")
            return self._assessments[assessment_id]

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if system_id not in self._retired:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return self._retired[system_id]

    def assessments_for(self, system_id: str, seq: int) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._assessments[i] for i in self._system_assessments.get(system_id, [])
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._system_assessments))

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._assessments))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_COMPLIANCE_VERSION,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: exercise assess -> verify -> evaluate."""
    ledger = AICompliance()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.assess(
        "system-1",
        1,
        compliance_kind="regulatory-compliance",
        verdict="compliant",
    )
    assert rec.verify()
    rep = ledger.verify(rec.assessment_id, 2)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("system-1", 3)
    assert ev.posture == "compliant"
    ret = ledger.retire("system-1", 4)
    assert ret.verify()
    print("ai-compliance OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
