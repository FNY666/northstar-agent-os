"""AI ethics incident: ethics-incident report/investigate decision ledger, Simulated.

Research note: AI ethics incidents are where ethics governance meets
the real world - when an AI system is alleged to have violated an
ethics property (bias violation, fairness violation, discrimination
harm, privacy violation, autonomy violation, dignity violation), the
host declares what was reported, at what host-reported severity, and
what investigations were declared against it. This module is the
*decision ledger* for declared AI ethics incidents: which
ethics-incident ids had which reports booked (over a pinned
ethics-incident-kind vocabulary), what declared investigations were
booked against them, and what ethics posture the ledger derives -
defensible bookkeeping, never proof that a real ethics incident
occurred or that it was really understood.

This module owns the report -> investigate -> verify lifecycle:

* **report()** - book one declared ethics-incident report (minted
  ``eir-N`` ids; pinned ethics-incident-kind vocabulary over the
  common ethics-incident classes; host-reported severity int in
  [0,100] booked *as data*); the first report registers its
  ethics incident; raw ethics reports, harm narratives, claimant
  identities, and forensic material never enter records - digest pins
  only.
* **investigate()** - book one declared investigation (minted
  ``inv-N`` ids; pinned finding vocabulary booked *as data*);
  chainable; fail-closed on unknown or retired ethics incidents.
* **verify()** - **pure read**: re-derive one report or investigation
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the investigation really happened.
* **evaluate()** - **pure read**: derive one ethics incident's posture
  as data (``critical-open`` -> ``open`` -> ``under-review`` ->
  ``mitigated`` -> ``resolved``) with report/investigation tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of an ethics-incident id; ids are
  never recycled.

Distinct-layer rationale vs siblings: ``ai_incident.py`` owns the
general incident lifecycle (capability-misuse / misalignment /
deceptive-behavior / data-breach classes); ``ai_ethics.py`` owns the
ethics assessment -> mitigation lifecycle (declared ethics findings
and their mitigations); ``ai_safety_incident.py`` owns safety-incident
declaration and investigation (unsafe-output / policy-bypass /
containment-breach classes); ``ai_oversight.py`` owns oversight
sessions; ``ai_redress.py`` owns remedy provisions against claims -
this module is the *ethics-incident* declaration ledger none of them
own: declared ethics incidents over a pinned ethics-incident-kind
vocabulary, declared ethics investigations, digest re-derivation, and
the ledger-rule ethics posture that turns declared reports and
findings into an ethics claim, always as data, never as measured
ethics truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-ethics-incident.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module investigates nothing, proves nothing about
real-world ethics incidents, and finds no real harm. A booked
``resolved`` posture means "the host declared it", never "the ethics
incident is fixed"; a booked ``harm-confirmed`` finding means "the
host declared it", never "real harm was measured". Ethics reports,
harm narratives, claimant identities, reporter identities, ethics
review material, and raw forensic material never enter records or cross
the audit boundary - digest pins only.
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
AI_ETHICS_INCIDENT_VERSION = "ai-ethics-incident.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-ethics-incident.v1"

#: Pinned ethics-incident-kind vocabulary (the ethics-incident classes).
ETHICS_INCIDENT_KINDS = (
    "bias-violation",
    "fairness-violation",
    "discrimination-harm",
    "privacy-violation",
    "autonomy-violation",
    "dignity-violation",
    "transparency-failure",
    "ethics-near-miss",
)

#: Pinned investigation-finding vocabulary (booked as data, never proof).
INVESTIGATION_FINDINGS = (
    "harm-confirmed",
    "harm-refuted",
    "root-cause-found",
    "contained",
    "inconclusive",
    "resolved",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived postures (booked as data), with precedence order
#: critical-open > open > under-review > mitigated > resolved.
POSTURES = (
    "unreported",
    "critical-open",
    "open",
    "under-review",
    "mitigated",
    "resolved",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Severity at or above which an uninvestigated ethics incident is critical.
CRITICAL_SEVERITY = 75

#: Audit kinds emitted by this module.
EMIT_KINDS = (
    "reported",
    "investigated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (pinned vocabulary
#: values and digest pins remain emittable as declared data).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "guardrail",
        "guardrails",
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
        "weights_file",
        "checkpoint_data",
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
        "heartbeat",
        "behavior",
        "demonstration",
        "preference",
        "feedback",
        "reward",
        "evidence",
        "findings",
        "report",
        "reports",
        "ethics_report",
        "ethics_report_text",
        "ethics_violation",
        "ethics_narrative",
        "bias_analysis",
        "bias_claim",
        "discrimination_claim",
        "fairness_narrative",
        "claimant_statement",
        "workpapers",
        "interview",
        "interviews",
        "questionnaire",
        "checklist",
        "incident",
        "incident_description",
        "incident_details",
        "incident_text",
        "incident_report_text",
        "impact",
        "impact_assessment",
        "impact_narrative",
        "harm",
        "harm_description",
        "harm_narrative",
        "injury",
        "damage",
        "damages",
        "victim",
        "victim_id",
        "victim_identity",
        "reporter",
        "reporter_id",
        "reporter_identity",
        "forensics",
        "forensic_data",
        "timeline",
        "root_cause",
        "causal_chain",
        "attack_chain",
        "exploit",
        "payload",
        "contact",
        "contact_details",
        "address",
        "phone",
        "email",
        "personal_data",
        "personal_information",
        "identity",
        "identity_document",
        "document",
        "documents",
        "medical_record",
        "financial_record",
        "settlement",
        "settlement_terms",
        "agreement",
        "legal_filing",
        "court_order",
        "claim",
        "claim_details",
        "claim_text",
        "compensation_amount",
        "payout",
        "payment",
        "payment_details",
        "bank_details",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AIEthicsIncidentError(Exception):
    """Base class for all ai-ethics-incident ledger errors."""


class BadEthicsIncidentError(AIEthicsIncidentError):
    pass


class UnknownEthicsIncidentError(AIEthicsIncidentError):
    pass


class RetiredEthicsIncidentError(AIEthicsIncidentError):
    pass


class BadEthicsIncidentKindError(AIEthicsIncidentError):
    pass


class BadSeverityError(AIEthicsIncidentError):
    pass


class BadFindingError(AIEthicsIncidentError):
    pass


class BadDigestError(AIEthicsIncidentError):
    pass


class BadReasonError(AIEthicsIncidentError):
    pass


class UnknownRecordError(AIEthicsIncidentError):
    pass


class SeqOrderError(AIEthicsIncidentError):
    pass


class AuditKindError(AIEthicsIncidentError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadEthicsIncidentError(f"{what} must be a non-empty string")
    return value


def _check_ethics_incident_kind(value: Any) -> str:
    if value not in ETHICS_INCIDENT_KINDS:
        raise BadEthicsIncidentKindError(
            f"ethics_incident_kind must be one of {ETHICS_INCIDENT_KINDS}"
        )
    return value


def _check_severity(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSeverityError("severity must be an int in [0, 100]")
    if not 0 <= value <= 100:
        raise BadSeverityError("severity must be an int in [0, 100]")
    return value


def _check_finding(value: Any) -> str:
    if value not in INVESTIGATION_FINDINGS:
        raise BadFindingError(f"finding must be one of {INVESTIGATION_FINDINGS}")
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
class EthicsIncidentReport:
    report_id: str
    ethics_incident_id: str
    seq: int
    ethics_incident_kind: str
    severity: int
    report_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _report_payload(self), "ai-ethics-incident.report"
        )


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    ethics_incident_id: str
    seq: int
    finding: str
    investigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _investigate_payload(self), "ai-ethics-incident.investigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    ethics_incident_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-ethics-incident.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    record_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "ai-ethics-incident.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    ethics_incident_id: str
    seq: int
    posture: str
    n_reports: int
    n_investigations: int
    n_critical: int
    n_resolved: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-ethics-incident.evaluate"
        )


def _report_payload(rec: "EthicsIncidentReport") -> Dict[str, Any]:
    return {
        "report_id": rec.report_id,
        "ethics_incident_id": rec.ethics_incident_id,
        "seq": rec.seq,
        "ethics_incident_kind": rec.ethics_incident_kind,
        "severity": rec.severity,
        "report_digest": rec.report_digest,
    }


def _investigate_payload(rec: "InvestigationRecord") -> Dict[str, Any]:
    return {
        "investigation_id": rec.investigation_id,
        "ethics_incident_id": rec.ethics_incident_id,
        "seq": rec.seq,
        "finding": rec.finding,
        "investigation_digest": rec.investigation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {
        "ethics_incident_id": rec.ethics_incident_id,
        "seq": rec.seq,
        "reason": rec.reason,
    }


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "ethics_incident_id": rep.ethics_incident_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_reports": rep.n_reports,
        "n_investigations": rep.n_investigations,
        "n_critical": rep.n_critical,
        "n_resolved": rep.n_resolved,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_ethics_incident_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AIEthicsIncidentError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-ethics-incident",
        "version": AI_ETHICS_INCIDENT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIEthicsIncident:
    """AI-ethics-incident report/investigate decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All severities, findings,
    and postures are booked as data - never proof that a real ethics
    incident occurred or that it was really understood.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, EthicsIncidentReport] = {}
        self._investigations: Dict[str, InvestigationRecord] = {}
        self._incident_reports: Dict[str, List[str]] = {}
        self._incident_investigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._report_counter = 0
        self._investigation_counter = 0
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
            row = ai_ethics_incident_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-ethics-incident",
                "version": AI_ETHICS_INCIDENT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_ethics_incident_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, ethics_incident_id: str) -> None:
        if ethics_incident_id in self._retired:
            raise RetiredEthicsIncidentError(
                f"ethics incident is retired: {ethics_incident_id!r}"
            )

    # -- mutations ---------------------------------------------------------

    def report(
        self,
        ethics_incident_id: str,
        seq: int,
        ethics_incident_kind: str = "bias-violation",
        severity: int = 0,
        report_digest: str = "",
    ) -> EthicsIncidentReport:
        """Book one declared ethics-incident report (minted ``eir-N`` id).

        The first report on an id registers the ethics incident. Raw
        ethics reports, harm narratives, claimant and reporter
        identities, ethics review material, and forensic material never
        enter records - digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``ai-ethics-incident.rejected`` row; rewinds
        raise bare.
        """
        with self._lock:
            try:
                ethics_incident_id = _check_id(ethics_incident_id, "ethics_incident_id")
                self._require_seq(seq)
                ethics_incident_kind = _check_ethics_incident_kind(ethics_incident_kind)
                severity = _check_severity(severity)
                report_digest = _check_digest(report_digest, "report_digest")
                self._require_live(ethics_incident_id)
            except AIEthicsIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._report_counter += 1
            report_id = f"eir-{self._report_counter}"
            provisional = EthicsIncidentReport(
                report_id=report_id,
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                ethics_incident_kind=ethics_incident_kind,
                severity=severity,
                report_digest=report_digest,
                digest="",
            )
            digest = _digest_pin(
                _report_payload(provisional), "ai-ethics-incident.report"
            )
            rec = EthicsIncidentReport(
                report_id=report_id,
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                ethics_incident_kind=ethics_incident_kind,
                severity=severity,
                report_digest=report_digest,
                digest=digest,
            )
            self._reports[report_id] = rec
            self._incident_reports.setdefault(ethics_incident_id, []).append(report_id)
            self._emit(
                "reported",
                seq,
                report_id=report_id,
                ethics_incident_id=ethics_incident_id,
                ethics_incident_kind=ethics_incident_kind,
                severity=severity,
                report_digest=report_digest,
            )
            return rec

    def investigate(
        self,
        ethics_incident_id: str,
        seq: int,
        finding: str = "inconclusive",
        investigation_digest: str = "",
    ) -> InvestigationRecord:
        """Book one declared investigation (minted ``inv-N`` id).

        Repeatable chain: many investigations may be booked against one
        ethics incident. Fail-closed on unknown or retired ethics
        incidents; the finding is booked as data, never proof the
        ethics incident was really understood.
        """
        with self._lock:
            try:
                ethics_incident_id = _check_id(ethics_incident_id, "ethics_incident_id")
                self._require_seq(seq)
                finding = _check_finding(finding)
                investigation_digest = _check_digest(
                    investigation_digest, "investigation_digest"
                )
                self._require_live(ethics_incident_id)
                if ethics_incident_id not in self._incident_reports:
                    raise UnknownEthicsIncidentError(
                        f"unknown ethics incident: {ethics_incident_id!r}"
                    )
            except AIEthicsIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._investigation_counter += 1
            investigation_id = f"inv-{self._investigation_counter}"
            provisional = InvestigationRecord(
                investigation_id=investigation_id,
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest="",
            )
            digest = _digest_pin(
                _investigate_payload(provisional), "ai-ethics-incident.investigate"
            )
            rec = InvestigationRecord(
                investigation_id=investigation_id,
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest=digest,
            )
            self._investigations[investigation_id] = rec
            self._incident_investigations.setdefault(ethics_incident_id, []).append(
                investigation_id
            )
            self._emit(
                "investigated",
                seq,
                investigation_id=investigation_id,
                ethics_incident_id=ethics_incident_id,
                finding=finding,
                investigation_digest=investigation_digest,
            )
            return rec

    def retire(
        self, ethics_incident_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a ethics-incident id; ids are never recycled."""
        with self._lock:
            try:
                ethics_incident_id = _check_id(ethics_incident_id, "ethics_incident_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if ethics_incident_id in self._retired:
                    raise RetiredEthicsIncidentError(
                        f"ethics incident is retired: {ethics_incident_id!r}"
                    )
                if ethics_incident_id not in self._incident_reports:
                    raise UnknownEthicsIncidentError(
                        f"unknown ethics incident: {ethics_incident_id!r}"
                    )
            except AIEthicsIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                ethics_incident_id=ethics_incident_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-ethics-incident.retire"
            )
            rec = RetireRecord(
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                reason=reason,
                digest=digest,
            )
            self._retired[ethics_incident_id] = rec
            self._emit("retired", seq, ethics_incident_id=ethics_incident_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one report or investigation digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the investigation really happened. Seq is shape-validated
        only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            rec = self._reports.get(record_id)
            if rec is None:
                rec = self._investigations.get(record_id)
            if rec is None or isinstance(record_id, bool) or not isinstance(
                record_id, str
            ):
                raise UnknownRecordError(f"unknown record id: {record_id!r}")
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-ethics-incident.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, ethics_incident_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one ethics incident's posture as data.

        Posture by ledger rule: ``critical-open`` (any uninvestigated
        report with severity >= 75) -> ``open`` (any report without an
        investigation, or any harm-confirmed finding) ->
        ``under-review`` (any inconclusive finding) -> ``mitigated``
        (all findings contained or root-cause-found) -> ``resolved``
        (all findings resolved or harm-refuted). ``integrity_ok``
        re-derives all in-scope digest pins as data. Seq is
        shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            ethics_incident_id = _check_id(ethics_incident_id, "ethics_incident_id")
            if ethics_incident_id not in self._incident_reports:
                raise UnknownEthicsIncidentError(
                    f"unknown ethics incident: {ethics_incident_id!r}"
                )
            report_ids = self._incident_reports[ethics_incident_id]
            reports = [self._reports[i] for i in report_ids]
            inv_ids = self._incident_investigations.get(ethics_incident_id, [])
            investigations = [self._investigations[i] for i in inv_ids]
            n_critical = sum(1 for r in reports if r.severity >= CRITICAL_SEVERITY)
            n_resolved = sum(1 for i in investigations if i.finding == "resolved")
            if not investigations:
                if any(r.severity >= CRITICAL_SEVERITY for r in reports):
                    posture = "critical-open"
                else:
                    posture = "open"
            else:
                findings = [i.finding for i in investigations]
                if any(f == "inconclusive" for f in findings):
                    posture = "under-review"
                elif any(f == "harm-confirmed" for f in findings):
                    posture = "open"
                elif all(f in ("contained", "root-cause-found") for f in findings):
                    posture = "mitigated"
                elif all(f in ("resolved", "harm-refuted") for f in findings):
                    posture = "resolved"
                else:
                    posture = "unreported"
            integrity_ok = all(r.verify() for r in reports) and all(
                i.verify() for i in investigations
            )
            provisional = EvaluationReport(
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                posture=posture,
                n_reports=len(reports),
                n_investigations=len(investigations),
                n_critical=n_critical,
                n_resolved=n_resolved,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-ethics-incident.evaluate"
            )
            return EvaluationReport(
                ethics_incident_id=ethics_incident_id,
                seq=seq,
                posture=posture,
                n_reports=len(reports),
                n_investigations=len(investigations),
                n_critical=n_critical,
                n_resolved=n_resolved,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def ethics_incident_record(
        self, report_id: str, seq: int
    ) -> EthicsIncidentReport:
        with self._lock:
            self._check_read_seq(seq)
            if report_id not in self._reports:
                raise UnknownRecordError(f"unknown report id: {report_id!r}")
            return self._reports[report_id]

    def investigation_record(
        self, investigation_id: str, seq: int
    ) -> InvestigationRecord:
        with self._lock:
            self._check_read_seq(seq)
            if investigation_id not in self._investigations:
                raise UnknownRecordError(
                    f"unknown investigation id: {investigation_id!r}"
                )
            return self._investigations[investigation_id]

    def reports_for(
        self, ethics_incident_id: str, seq: int
    ) -> Tuple[EthicsIncidentReport, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._reports[i]
                for i in self._incident_reports.get(ethics_incident_id, [])
            )

    def investigations_for(
        self, ethics_incident_id: str, seq: int
    ) -> Tuple[InvestigationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._investigations[i]
                for i in self._incident_investigations.get(ethics_incident_id, [])
            )

    def ethics_incident_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._incident_reports))

    def report_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._reports))

    def investigation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._investigations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_ethics_incidents": len(self._incident_reports),
                "n_reports": len(self._reports),
                "n_investigations": len(self._investigations),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_ETHICS_INCIDENT_VERSION,
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
    """Self-check: exercise report -> investigate -> verify -> evaluate."""
    ledger = AIEthicsIncident()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.report(
        "ethics-1", 1, ethics_incident_kind="bias-violation", severity=10
    )
    assert rec.verify()
    inv = ledger.investigate("ethics-1", 2, finding="resolved")
    assert inv.verify()
    rep = ledger.verify(rec.report_id, 3)
    assert rep.verdict == "verified"
    rep2 = ledger.verify(inv.investigation_id, 4)
    assert rep2.verdict == "verified"
    ev = ledger.evaluate("ethics-1", 5)
    assert ev.posture == "resolved"
    ret = ledger.retire("ethics-1", 6)
    assert ret.verify()
    print(
        "ai-ethics-incident OK: report, investigate, verify, evaluate, retire, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
