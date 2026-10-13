"""AI traceability incident: traceability-incident report/investigate decision ledger, Simulated.

Research note: AI traceability incidents are where traceability
governance meets the real world - when an AI system's decision trail,
data lineage, or provenance chain is alleged to have a gap (lineage
gap, provenance loss, record tampering, chain-of-custody break,
reproducibility failure, version-lineage drift, traceability blind
spot, traceability near-miss), the host declares what was reported, at
what host-reported severity, and what investigations were declared
against it. This module is the *decision ledger* for declared AI
traceability incidents: which traceability-incident ids had which
reports booked (over a pinned traceability-incident-kind vocabulary),
what declared investigations were booked against them, and what
traceability posture the ledger derives - defensible bookkeeping, never
proof that a real traceability incident occurred or that it was really
understood.

This module owns the report -> investigate -> verify lifecycle:

* **report()** - book one declared traceability-incident report (minted
  ``tri-N`` ids; pinned traceability-incident-kind vocabulary over the
  common traceability-incident classes; host-reported severity int in
  [0,100] booked *as data*); the first report registers its traceability
  incident; raw lineage records, provenance chains, audit trails,
  claimant and reporter identities, review material, and forensic
  material never enter records - digest pins only.
* **investigate()** - book one declared investigation (minted
  ``inv-N`` ids; pinned finding vocabulary booked *as data*);
  chainable; fail-closed on unknown or retired traceability incidents.
* **verify()** - **pure read**: re-derive one report or investigation
  record's digest pin; verdict ``verified`` / ``tampered`` booked as
  data, never as proof the investigation really happened.
* **evaluate()** - **pure read**: derive one traceability incident's posture
  as data (``critical-open`` -> ``open`` -> ``under-review`` ->
  ``mitigated`` -> ``resolved``) with report/investigation tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of an traceability-incident id; ids are
  never recycled.

Distinct-layer rationale vs siblings: ``ai_incident.py`` owns the
general incident lifecycle (capability-misuse / misalignment /
deceptive-behavior / data-breach classes); ``traceability_paradox.py``
owns traceability-paradox analysis (the tension between full
traceability and privacy/compute cost), not incident declarations;
``ai_safety_incident.py`` owns safety-incident declaration and
investigation (unsafe-output / policy-bypass / containment-breach
classes); ``ai_ethics_incident.py`` owns ethics-incident declaration and
investigation (bias-violation / fairness-violation / discrimination-harm
classes); ``ai_fairness_incident.py`` owns fairness-incident declaration
and investigation (algorithmic-bias / disparate-impact classes);
``ai_transparency_incident.py`` owns transparency-incident declaration and
investigation (disclosure-omission / opaque-decision classes);
``ai_accountability_incident.py`` owns accountability-incident declaration
and investigation (oversight-failure / accountability-gap /
responsibility-denial classes); ``ai_oversight_incident.py`` owns
oversight-incident declaration and investigation (oversight-evasion /
human-oversight-failure / oversight-blind-spot classes);
``ai_compliance_incident.py`` owns compliance-incident declaration and
investigation (regulatory-violation / policy-breach /
standard-noncompliance classes) - this module owns
the *traceability-incident* declaration ledger: declared traceability incidents
over a pinned traceability-incident-kind vocabulary, declared traceability
investigations, digest re-derivation, and the ledger-rule traceability
posture that turns declared reports and findings into a traceability claim,
always as data, never as measured traceability truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-traceability-incident.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module investigates nothing, proves nothing about
real-world traceability incidents, and finds no real harm. A booked
``resolved`` posture means "the host declared it", never "the traceability
incident is fixed"; a booked ``harm-confirmed`` finding means "the
host declared it", never "real harm was measured". Lineage records,
provenance chains, audit trails, claimant identities, reporter identities,
review material, decision traces, and raw forensic material never enter records
or cross the audit boundary - digest pins only.
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
AI_TRACEABILITY_INCIDENT_VERSION = "ai-traceability-incident.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-traceability-incident.v1"

#: Pinned traceability-incident-kind vocabulary (the traceability-incident classes).
TRACEABILITY_INCIDENT_KINDS = (
    "lineage-gap",
    "provenance-loss",
    "record-tampering",
    "chain-of-custody-break",
    "reproducibility-failure",
    "version-lineage-drift",
    "traceability-blind-spot",
    "traceability-near-miss",
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

#: Severity at or above which an uninvestigated traceability incident is critical.
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
        "traceability_report",
        "traceability_report_text",
        "traceability_violation",
        "traceability_narrative",
        "lineage_gap",
        "lineage_gap_evidence",
        "provenance_analysis",
        "traceability_ratio",
        "unattributed_lineage",
        "unattributed_provenance",
        "lineage_record",
        "provenance_breakdown",
        "traceability_metric",
        "traceability_metric_value",
        "lineage_workpaper",
        "provenance_audit",
        "provenance_audit_report",
        "chain_of_custody_log",
        "chain_of_custody_log_text",
        "traceability_audit_material",
        "lineage_analysis_record",
        "trace_claim",
        "lineage_claim",
        "claimant_statement_traceability",
        "provenance_workpapers",
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
        "traceability_officer_record",
        "lineage_board_minutes",
        "lineage_board_finding",
        "escalation_log",
        "escalation_record",
        "traceability_intervention",
        "traceability_decision",
        "traceability_charter",
        "traceability_policy",
        "lineage_assignment",
        "traceability_coverage",
        "audit_trail",
        "audit_trail_text",
        "decision_trace",
        "decision_lineage",
        "provenance_chain",
        "chain_of_custody",
        "version_lineage",
        "reproducibility_log",
        "tamper_evidence",
        "record_snapshot",
        "log_archive",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AITraceabilityIncidentError(Exception):
    """Base class for all ai-traceability-incident ledger errors."""


class BadTraceabilityIncidentError(AITraceabilityIncidentError):
    pass


class UnknownTraceabilityIncidentError(AITraceabilityIncidentError):
    pass


class RetiredTraceabilityIncidentError(AITraceabilityIncidentError):
    pass


class BadTraceabilityIncidentKindError(AITraceabilityIncidentError):
    pass


class BadSeverityError(AITraceabilityIncidentError):
    pass


class BadFindingError(AITraceabilityIncidentError):
    pass


class BadDigestError(AITraceabilityIncidentError):
    pass


class BadReasonError(AITraceabilityIncidentError):
    pass


class UnknownRecordError(AITraceabilityIncidentError):
    pass


class SeqOrderError(AITraceabilityIncidentError):
    pass


class AuditKindError(AITraceabilityIncidentError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadTraceabilityIncidentError(f"{what} must be a non-empty string")
    return value


def _check_traceability_incident_kind(value: Any) -> str:
    if value not in TRACEABILITY_INCIDENT_KINDS:
        raise BadTraceabilityIncidentKindError(
            f"traceability_incident_kind must be one of {TRACEABILITY_INCIDENT_KINDS}"
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
class TraceabilityIncidentReport:
    report_id: str
    traceability_incident_id: str
    seq: int
    traceability_incident_kind: str
    severity: int
    report_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _report_payload(self), "ai-traceability-incident.report"
        )


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    traceability_incident_id: str
    seq: int
    finding: str
    investigation_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _investigate_payload(self), "ai-traceability-incident.investigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    traceability_incident_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-traceability-incident.retire"
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
            _verify_payload(self), "ai-traceability-incident.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    traceability_incident_id: str
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
            _evaluate_payload(self), "ai-traceability-incident.evaluate"
        )


def _report_payload(rec: "TraceabilityIncidentReport") -> Dict[str, Any]:
    return {
        "report_id": rec.report_id,
        "traceability_incident_id": rec.traceability_incident_id,
        "seq": rec.seq,
        "traceability_incident_kind": rec.traceability_incident_kind,
        "severity": rec.severity,
        "report_digest": rec.report_digest,
    }


def _investigate_payload(rec: "InvestigationRecord") -> Dict[str, Any]:
    return {
        "investigation_id": rec.investigation_id,
        "traceability_incident_id": rec.traceability_incident_id,
        "seq": rec.seq,
        "finding": rec.finding,
        "investigation_digest": rec.investigation_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {
        "traceability_incident_id": rec.traceability_incident_id,
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
        "traceability_incident_id": rep.traceability_incident_id,
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


def ai_traceability_incident_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
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
            raise AITraceabilityIncidentError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-traceability-incident",
        "version": AI_TRACEABILITY_INCIDENT_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AITraceabilityIncident:
    """AI-traceability-incident report/investigate decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All severities, findings,
    and postures are booked as data - never proof that a real traceability
    incident occurred or that it was really understood.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, TraceabilityIncidentReport] = {}
        self._investigations: Dict[str, InvestigationRecord] = {}
        self._traceability_incident_reports: Dict[str, List[str]] = {}
        self._traceability_incident_investigations: Dict[str, List[str]] = {}
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
            row = ai_traceability_incident_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-traceability-incident",
                "version": AI_TRACEABILITY_INCIDENT_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_traceability_incident_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, traceability_incident_id: str) -> None:
        if traceability_incident_id in self._retired:
            raise RetiredTraceabilityIncidentError(
                f"traceability incident is retired: {traceability_incident_id!r}"
            )

    # -- mutations ---------------------------------------------------------

    def report(
        self,
        traceability_incident_id: str,
        seq: int,
        traceability_incident_kind: str = "lineage-gap",
        severity: int = 0,
        report_digest: str = "",
    ) -> TraceabilityIncidentReport:
        """Book one declared traceability-incident report (minted ``cir-N`` id).

        The first report on an id registers the traceability incident. Raw
        traceability reports, disclosure texts, claimant and reporter
        identities, review material, and forensic material never
        enter records - digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``ai-traceability-incident.rejected`` row; rewinds
        raise bare.
        """
        with self._lock:
            try:
                traceability_incident_id = _check_id(traceability_incident_id, "traceability_incident_id")
                self._require_seq(seq)
                traceability_incident_kind = _check_traceability_incident_kind(traceability_incident_kind)
                severity = _check_severity(severity)
                report_digest = _check_digest(report_digest, "report_digest")
                self._require_live(traceability_incident_id)
            except AITraceabilityIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._report_counter += 1
            report_id = f"tri-{self._report_counter}"
            provisional = TraceabilityIncidentReport(
                report_id=report_id,
                traceability_incident_id=traceability_incident_id,
                seq=seq,
                traceability_incident_kind=traceability_incident_kind,
                severity=severity,
                report_digest=report_digest,
                digest="",
            )
            digest = _digest_pin(
                _report_payload(provisional), "ai-traceability-incident.report"
            )
            rec = TraceabilityIncidentReport(
                report_id=report_id,
                traceability_incident_id=traceability_incident_id,
                seq=seq,
                traceability_incident_kind=traceability_incident_kind,
                severity=severity,
                report_digest=report_digest,
                digest=digest,
            )
            self._reports[report_id] = rec
            self._traceability_incident_reports.setdefault(traceability_incident_id, []).append(report_id)
            self._emit(
                "reported",
                seq,
                report_id=report_id,
                traceability_incident_id=traceability_incident_id,
                traceability_incident_kind=traceability_incident_kind,
                severity=severity,
                report_digest=report_digest,
            )
            return rec

    def investigate(
        self,
        traceability_incident_id: str,
        seq: int,
        finding: str = "inconclusive",
        investigation_digest: str = "",
    ) -> InvestigationRecord:
        """Book one declared investigation (minted ``inv-N`` id).

        Repeatable chain: many investigations may be booked against one
        traceability incident. Fail-closed on unknown or retired traceability
        incidents; the finding is booked as data, never proof the
        traceability incident was really understood.
        """
        with self._lock:
            try:
                traceability_incident_id = _check_id(traceability_incident_id, "traceability_incident_id")
                self._require_seq(seq)
                finding = _check_finding(finding)
                investigation_digest = _check_digest(
                    investigation_digest, "investigation_digest"
                )
                self._require_live(traceability_incident_id)
                if traceability_incident_id not in self._traceability_incident_reports:
                    raise UnknownTraceabilityIncidentError(
                        f"unknown traceability incident: {traceability_incident_id!r}"
                    )
            except AITraceabilityIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._investigation_counter += 1
            investigation_id = f"inv-{self._investigation_counter}"
            provisional = InvestigationRecord(
                investigation_id=investigation_id,
                traceability_incident_id=traceability_incident_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest="",
            )
            digest = _digest_pin(
                _investigate_payload(provisional), "ai-traceability-incident.investigate"
            )
            rec = InvestigationRecord(
                investigation_id=investigation_id,
                traceability_incident_id=traceability_incident_id,
                seq=seq,
                finding=finding,
                investigation_digest=investigation_digest,
                digest=digest,
            )
            self._investigations[investigation_id] = rec
            self._traceability_incident_investigations.setdefault(traceability_incident_id, []).append(
                investigation_id
            )
            self._emit(
                "investigated",
                seq,
                investigation_id=investigation_id,
                traceability_incident_id=traceability_incident_id,
                finding=finding,
                investigation_digest=investigation_digest,
            )
            return rec

    def retire(
        self, traceability_incident_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a traceability-incident id; ids are never recycled."""
        with self._lock:
            try:
                traceability_incident_id = _check_id(traceability_incident_id, "traceability_incident_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if traceability_incident_id in self._retired:
                    raise RetiredTraceabilityIncidentError(
                        f"traceability incident is retired: {traceability_incident_id!r}"
                    )
                if traceability_incident_id not in self._traceability_incident_reports:
                    raise UnknownTraceabilityIncidentError(
                        f"unknown traceability incident: {traceability_incident_id!r}"
                    )
            except AITraceabilityIncidentError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                traceability_incident_id=traceability_incident_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-traceability-incident.retire"
            )
            rec = RetireRecord(
                traceability_incident_id=traceability_incident_id,
                seq=seq,
                reason=reason,
                digest=digest,
            )
            self._retired[traceability_incident_id] = rec
            self._emit("retired", seq, traceability_incident_id=traceability_incident_id, reason=reason)
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
                _verify_payload(provisional), "ai-traceability-incident.verify"
            )
            return VerificationReport(
                record_id=record_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, traceability_incident_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one traceability incident's posture as data.

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
            traceability_incident_id = _check_id(traceability_incident_id, "traceability_incident_id")
            if traceability_incident_id not in self._traceability_incident_reports:
                raise UnknownTraceabilityIncidentError(
                    f"unknown traceability incident: {traceability_incident_id!r}"
                )
            report_ids = self._traceability_incident_reports[traceability_incident_id]
            reports = [self._reports[i] for i in report_ids]
            inv_ids = self._traceability_incident_investigations.get(traceability_incident_id, [])
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
                traceability_incident_id=traceability_incident_id,
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
                _evaluate_payload(provisional), "ai-traceability-incident.evaluate"
            )
            return EvaluationReport(
                traceability_incident_id=traceability_incident_id,
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

    def traceability_incident_record(
        self, report_id: str, seq: int
    ) -> TraceabilityIncidentReport:
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
        self, traceability_incident_id: str, seq: int
    ) -> Tuple[TraceabilityIncidentReport, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._reports[i]
                for i in self._traceability_incident_reports.get(traceability_incident_id, [])
            )

    def investigations_for(
        self, traceability_incident_id: str, seq: int
    ) -> Tuple[InvestigationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._investigations[i]
                for i in self._traceability_incident_investigations.get(traceability_incident_id, [])
            )

    def traceability_incident_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._traceability_incident_reports))

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
                "n_traceability_incidents": len(self._traceability_incident_reports),
                "n_reports": len(self._reports),
                "n_investigations": len(self._investigations),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_TRACEABILITY_INCIDENT_VERSION,
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
    ledger = AITraceabilityIncident()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.report(
        "traceability-1", 1, traceability_incident_kind="lineage-gap", severity=10
    )
    assert rec.verify()
    inv = ledger.investigate("traceability-1", 2, finding="resolved")
    assert inv.verify()
    rep = ledger.verify(rec.report_id, 3)
    assert rep.verdict == "verified"
    rep2 = ledger.verify(inv.investigation_id, 4)
    assert rep2.verdict == "verified"
    ev = ledger.evaluate("traceability-1", 5)
    assert ev.posture == "resolved"
    ret = ledger.retire("traceability-1", 6)
    assert ret.verify()
    print(
        "ai-traceability-incident OK: report, investigate, verify, evaluate, retire, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
