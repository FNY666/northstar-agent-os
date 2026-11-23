"""AI compliance mitigation: declared compliance-hazard mitigation decision ledger, Simulated.

Research note: AI compliance mitigation is the action side of AI
compliance governance - after an AI compliance hazard is declared
(non-conforming data practice, missing policy control, unmet
regulatory obligation, absent audit evidence, inadequate risk
control, undisclosed obligation), what mitigation action the host
declared it booked against that hazard, what compliance-mitigation
strategy the action claimed to follow, what implementation status and
declared effectiveness the host booked for it, and what
residual-compliance posture the ledger derives for the hazard. This
module is the *decision ledger* for declared AI compliance
mitigation actions: which hazards had which mitigations booked
(over a pinned compliance-mitigation vocabulary), what statuses and
effectiveness ratings were declared against them, and what residual
posture the ledger derives - defensible bookkeeping, never proof that
any hazard was really reduced.

This module owns the mitigate -> verify -> evaluate lifecycle:

* **mitigate()** - book one declared mitigation action against a
  compliance-hazard id (minted ``cmm-N`` ids; pinned
  compliance-mitigation strategy vocabulary over the classic
  compliance-treatment classes; status starts ``proposed``); the first
  mitigation on an id registers the hazard; raw hazard material,
  policy documents, audit workpapers, regulatory filings, and model
  artifacts never enter records - digest pins only.
* **update()** - book a declared status/effectiveness transition on one
  mitigation (fail-closed transition ladder; ``effectiveness`` is only
  settable when status is ``implemented``); the record is re-pinned.
* **verify()** - **pure read**: re-derive one mitigation record's digest
  pin; verdict ``verified`` / ``tampered`` booked as data, never as
  proof the mitigation really happened.
* **evaluate()** - **pure read**: derive one hazard's
  residual-compliance posture as data (``unmitigated`` ->
  ``under-mitigation`` -> ``ineffective`` -> ``mitigated`` ->
  ``partially-mitigated`` -> ``abandoned``) with mitigation tallies and
  a digest-pinned integrity flag.
* **retire()** - terminal retirement of a hazard id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_compliance.py`` owns the
AI-compliance-assessment lifecycle; ``compliance.py`` owns
framework-conformance check bookkeeping; ``compliance_checker.py``
owns compliance-check execution; ``compliance_reports.py`` owns
compliance-report generation; ``step_compliance.py`` owns per-step
compliance gating; ``ai_mitigation.py`` owns risk-mitigation actions
booked against declared *risk* ids with classic risk-treatment
strategies (avoid/reduce/transfer/accept/contain/monitor);
``ai_safety_mitigation.py`` owns *safety-hazard* mitigation actions;
``ai_ethics_mitigation.py`` owns *ethics-hazard* mitigation actions;
``ai_fairness_mitigation.py`` owns *fairness-hazard* mitigation
actions; ``ai_transparency_mitigation.py`` owns *transparency-hazard*
mitigation actions; ``ai_accountability_mitigation.py`` owns
*accountability-hazard* mitigation actions - this module is the
*compliance-hazard mitigation action* ledger none of them own:
declared mitigation actions booked against declared compliance-hazard
ids with compliance-treatment strategies, implementation-status and
declared-effectiveness transitions, digest re-derivation, and the
ledger-rule residual posture that turns declared mitigations into a
mitigation claim, always as data, never as measured hazard reduction.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``ai-compliance-mitigation.rejected`` row; rewinds raise bare
without consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module reduces no hazard, implements no control,
prevents nothing, and proves nothing about real-world compliance. A
booked ``mitigated`` posture means "the host declared it", never "the
hazard is gone"; a booked ``full`` effectiveness means "the host
declared it", never "the mitigation truly worked". Hazard material,
policy documents, audit workpapers, regulatory filings, traces, and
raw mitigation evidence never enter records or cross the audit boundary
- digest pins only.
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
AI_COMPLIANCE_MITIGATION_VERSION = "ai-compliance-mitigation.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-compliance-mitigation.v1"

#: Pinned compliance-mitigation strategy vocabulary (classic
#: compliance-treatment classes; booked as data, never proof).
COMPLIANCE_STRATEGIES = (
    "compliance-assignment",
    "policy-update",
    "control-implementation",
    "compliance-training",
    "audit-remediation",
    "exception-documentation",
    "regulatory-filing",
    "no-action",
)

#: Pinned implementation-status vocabulary (booked as data, never proof).
MITIGATION_STATUSES = (
    "proposed",
    "approved",
    "in-progress",
    "implemented",
    "abandoned",
)

#: Pinned declared-effectiveness vocabulary (only meaningful when the
#: mitigation status is ``implemented``; booked as data, never proof).
EFFECTIVENESS = (
    "unrated",
    "none",
    "partial",
    "full",
)

#: Pinned verify-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived residual-compliance postures (booked as data).
POSTURES = (
    "unmitigated",
    "under-mitigation",
    "ineffective",
    "mitigated",
    "partially-mitigated",
    "abandoned",
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
    "mitigated",
    "updated",
    "retired",
    "rejected",
)

#: Terminal statuses: no further transitions allowed.
TERMINAL_STATUSES = frozenset({"implemented", "abandoned"})

#: Fail-closed transition ladder.
ALLOWED_TRANSITIONS = {
    "proposed": frozenset({"approved", "abandoned"}),
    "approved": frozenset({"in-progress", "abandoned"}),
    "in-progress": frozenset({"implemented", "abandoned"}),
    "implemented": frozenset(),
    "abandoned": frozenset(),
}

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
        "checkpoint",
        "checkpoints",
        "backup",
        "backups",
        "restore_point",
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
        "evidence_text",
        "findings",
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
        "risk",
        "risk_text",
        "risk_detail",
        "risk_description",
        "risk_score",
        "risk_evidence",
        "hazard",
        "hazard_text",
        "hazard_detail",
        "hazard_description",
        "ethics_evidence",
        "ethics_report",
        "mitigation_text",
        "mitigation_detail",
        "mitigation_evidence",
        "ethics_assessment",
        "ethics_review",
        "ethics_case",
        "fairness_report",
        "bias_report",
        "discrimination_report",
        "complaint",
        "complaints",
        "complainant",
        "victim",
        "victims",
        "harm_narrative",
        "remedy",
        "remedy_plan",
        "disparate_impact_analysis",
        "demographic_data",
        "protected_class",
        "fairness_audit",
        "bias_evidence",
        "fairness_metric",
        "group_outcome",
        "demographic_parity_report",
        "equalized_odds_report",
        "calibration_report",
        "counterfactual_fairness",
        "representativeness_gap",
        "compliance_report",
        "compliance_assessment",
        "compliance_audit",
        "compliance_assignment",
        "compliance_charter",
        "human_review_record",
        "human_review_case",
        "intervention_case",
        "intervention_outcome",
        "compliance_officer",
        "officer_identity",
        "monitoring_report",
        "compliance_record",
        "escalation_record",
        "regulatory_filing",
        "regulatory_notice",
        "regulatory_evidence",
        "compliance_exception",
        "compliance_violation",
        "control_deficiency",
        "control_matrix",
        "compliance_certificate",
        "compliance_workpaper",
        "policy_document",
        "policy_text",
        "procedure_manual",
        "training_record",
        "training_content",
        "attestation",
        "attestation_text",
        "compliance_narrative",
        "regulator_identity",
        "remediation_plan_text",
        "transparency_report",
        "opacity_analysis",
        "opacity_report",
        "disclosure_record",
        "disclosure_text",
        "explanation",
        "explanation_text",
        "explanation_draft",
        "decision_log",
        "decision_log_text",
        "deliberation_log",
        "internal_design",
        "design_document",
        "proprietary_method",
        "trade_secret",
        "audit_trail_content",
        "traceability_log",
        "provenance_record",
        "evaluation_text",
        "redteam_output",
        "red_team_output",
        "pentest_output",
        "scan_output",
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


class AIComplianceMitigationError(Exception):
    """Base class for all ai-compliance-mitigation ledger errors."""


class BadHazardError(AIComplianceMitigationError):
    pass


class UnknownHazardError(AIComplianceMitigationError):
    pass


class RetiredHazardError(AIComplianceMitigationError):
    pass


class BadStrategyError(AIComplianceMitigationError):
    pass


class BadStatusError(AIComplianceMitigationError):
    pass


class BadEffectivenessError(AIComplianceMitigationError):
    pass


class BadTransitionError(AIComplianceMitigationError):
    pass


class BadDigestError(AIComplianceMitigationError):
    pass


class BadReasonError(AIComplianceMitigationError):
    pass


class UnknownMitigationError(AIComplianceMitigationError):
    pass


class SeqOrderError(AIComplianceMitigationError):
    pass


class AuditKindError(AIComplianceMitigationError):
    pass


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadHazardError(f"{what} must be a non-empty string")
    return value


def _check_strategy(value: Any) -> str:
    if value not in COMPLIANCE_STRATEGIES:
        raise BadStrategyError(f"strategy must be one of {COMPLIANCE_STRATEGIES}")
    return value


def _check_status(value: Any) -> str:
    if value not in MITIGATION_STATUSES:
        raise BadStatusError(f"status must be one of {MITIGATION_STATUSES}")
    return value


def _check_effectiveness(value: Any) -> str:
    if value not in EFFECTIVENESS:
        raise BadEffectivenessError(f"effectiveness must be one of {EFFECTIVENESS}")
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
class MitigationRecord:
    mitigation_id: str
    hazard_id: str
    seq: int
    strategy: str
    status: str
    effectiveness: str
    hazard_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _mitigate_payload(self), "ai-compliance-mitigation.mitigate"
        )


@dataclass(frozen=True)
class RetireRecord:
    hazard_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "ai-compliance-mitigation.retire"
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
            _verify_payload(self), "ai-compliance-mitigation.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    hazard_id: str
    seq: int
    posture: str
    n_mitigations: int
    n_implemented: int
    n_full: int
    n_partial: int
    n_none: int
    n_terminal: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "ai-compliance-mitigation.evaluate"
        )


def _mitigate_payload(rec: "MitigationRecord") -> Dict[str, Any]:
    return {
        "mitigation_id": rec.mitigation_id,
        "hazard_id": rec.hazard_id,
        "seq": rec.seq,
        "strategy": rec.strategy,
        "status": rec.status,
        "effectiveness": rec.effectiveness,
        "hazard_digest": rec.hazard_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"hazard_id": rec.hazard_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "record_id": rep.record_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "hazard_id": rep.hazard_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_mitigations": rep.n_mitigations,
        "n_implemented": rep.n_implemented,
        "n_full": rep.n_full,
        "n_partial": rep.n_partial,
        "n_none": rep.n_none,
        "n_terminal": rep.n_terminal,
        "integrity_ok": rep.integrity_ok,
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def ai_compliance_mitigation_audit_event(
    kind: str, seq: int, **detail: Any
) -> Dict[str, Any]:
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
            raise AIComplianceMitigationError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "ai-compliance-mitigation",
        "version": AI_COMPLIANCE_MITIGATION_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIComplianceMitigation:
    """AI compliance-hazard mitigation decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All outcomes are booked as
    data - never proof that any compliance hazard was really reduced
    (policy gap, control deficiency, unmet obligation, audit finding).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._hazard_mitigations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._mitigation_counter = 0
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
            row = ai_compliance_mitigation_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "module": "ai-compliance-mitigation",
                "version": AI_COMPLIANCE_MITIGATION_VERSION,
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            ai_compliance_mitigation_audit_event(audit_kind, seq, **details)
        )

    def _require_live(self, hazard_id: str) -> None:
        if hazard_id in self._retired:
            raise RetiredHazardError(f"hazard is retired: {hazard_id!r}")

    # -- mutations ---------------------------------------------------------

    def mitigate(
        self,
        hazard_id: str,
        seq: int,
        strategy: str = "compliance-assignment",
        hazard_digest: str = "",
    ) -> MitigationRecord:
        """Book one declared mitigation action (minted ``cmm-N`` id).

        The first mitigation on an id registers the hazard; the mitigation
        starts at status ``proposed`` with effectiveness ``unrated``.
        Raw hazard material, policy documents, audit workpapers,
        regulatory filings, and model artifacts never enter records -
        digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``ai-compliance-mitigation.rejected`` row;
        rewinds raise bare.
        """
        with self._lock:
            try:
                hazard_id = _check_id(hazard_id, "hazard_id")
                self._require_seq(seq)
                strategy = _check_strategy(strategy)
                hazard_digest = _check_digest(hazard_digest, "hazard_digest")
                self._require_live(hazard_id)
            except AIComplianceMitigationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._mitigation_counter += 1
            mitigation_id = f"cmm-{self._mitigation_counter}"
            provisional = MitigationRecord(
                mitigation_id=mitigation_id,
                hazard_id=hazard_id,
                seq=seq,
                strategy=strategy,
                status="proposed",
                effectiveness="unrated",
                hazard_digest=hazard_digest,
                digest="",
            )
            digest = _digest_pin(
                _mitigate_payload(provisional), "ai-compliance-mitigation.mitigate"
            )
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                hazard_id=hazard_id,
                seq=seq,
                strategy=strategy,
                status="proposed",
                effectiveness="unrated",
                hazard_digest=hazard_digest,
                digest=digest,
            )
            self._mitigations[mitigation_id] = rec
            self._hazard_mitigations.setdefault(hazard_id, []).append(mitigation_id)
            self._emit(
                "mitigated",
                seq,
                mitigation_id=mitigation_id,
                hazard_id=hazard_id,
                strategy=strategy,
                status="proposed",
                effectiveness="unrated",
                hazard_digest=hazard_digest,
            )
            return rec

    def update(
        self,
        mitigation_id: str,
        seq: int,
        status: str,
        effectiveness: str = "unrated",
    ) -> MitigationRecord:
        """Book a declared status/effectiveness transition on one mitigation.

        Fail-closed transition ladder; ``effectiveness`` may differ from
        ``unrated`` only when the target status is ``implemented``. The
        record is re-pinned (the seq is the update's seq). Fail-closed:
        failed mutations consume their seq and book an
        ``ai-compliance-mitigation.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                self._require_seq(seq)
                if (
                    isinstance(mitigation_id, bool)
                    or not isinstance(mitigation_id, str)
                    or mitigation_id not in self._mitigations
                ):
                    raise UnknownMitigationError(
                        f"unknown mitigation id: {mitigation_id!r}"
                    )
                status = _check_status(status)
                effectiveness = _check_effectiveness(effectiveness)
                current = self._mitigations[mitigation_id]
                self._require_live(current.hazard_id)
                if current.status in TERMINAL_STATUSES:
                    raise BadTransitionError(
                        f"mitigation {mitigation_id!r} is terminal at "
                        f"{current.status!r}"
                    )
                if status not in ALLOWED_TRANSITIONS[current.status]:
                    raise BadTransitionError(
                        f"transition {current.status!r} -> {status!r} not allowed"
                    )
                if status != "implemented" and effectiveness != "unrated":
                    raise BadEffectivenessError(
                        "effectiveness may only be rated for implemented mitigations"
                    )
            except AIComplianceMitigationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = MitigationRecord(
                mitigation_id=mitigation_id,
                hazard_id=current.hazard_id,
                seq=seq,
                strategy=current.strategy,
                status=status,
                effectiveness=effectiveness,
                hazard_digest=current.hazard_digest,
                digest="",
            )
            digest = _digest_pin(
                _mitigate_payload(provisional), "ai-compliance-mitigation.mitigate"
            )
            rec = MitigationRecord(
                mitigation_id=mitigation_id,
                hazard_id=current.hazard_id,
                seq=seq,
                strategy=current.strategy,
                status=status,
                effectiveness=effectiveness,
                hazard_digest=current.hazard_digest,
                digest=digest,
            )
            self._mitigations[mitigation_id] = rec
            self._emit(
                "updated",
                seq,
                mitigation_id=mitigation_id,
                hazard_id=current.hazard_id,
                old_status=current.status,
                status=status,
                effectiveness=effectiveness,
            )
            return rec

    def retire(
        self, hazard_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
        """Terminal retirement of a hazard id; ids are never recycled."""
        with self._lock:
            try:
                hazard_id = _check_id(hazard_id, "hazard_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if hazard_id in self._retired:
                    raise RetiredHazardError(f"hazard is retired: {hazard_id!r}")
                if hazard_id not in self._hazard_mitigations:
                    raise UnknownHazardError(f"unknown hazard: {hazard_id!r}")
            except AIComplianceMitigationError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                hazard_id=hazard_id, seq=seq, reason=reason, digest=""
            )
            digest = _digest_pin(
                _retire_payload(provisional), "ai-compliance-mitigation.retire"
            )
            rec = RetireRecord(
                hazard_id=hazard_id, seq=seq, reason=reason, digest=digest
            )
            self._retired[hazard_id] = rec
            self._emit("retired", seq, hazard_id=hazard_id, reason=reason)
            return rec

    # -- pure reads --------------------------------------------------------

    def _check_read_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        return seq

    def verify(self, mitigation_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one mitigation record's digest pin.

        Verdict ``verified`` / ``tampered`` booked as data, never as
        proof the mitigation really happened. Seq is shape-validated only -
        never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            if (
                isinstance(mitigation_id, bool)
                or not isinstance(mitigation_id, str)
                or mitigation_id not in self._mitigations
            ):
                raise UnknownMitigationError(
                    f"unknown mitigation id: {mitigation_id!r}"
                )
            rec = self._mitigations[mitigation_id]
            integrity_ok = rec.verify()
            verdict = "verified" if integrity_ok else "tampered"
            provisional = VerificationReport(
                record_id=mitigation_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _verify_payload(provisional), "ai-compliance-mitigation.verify"
            )
            return VerificationReport(
                record_id=mitigation_id,
                seq=seq,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    def evaluate(self, hazard_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one hazard's residual-compliance posture as data.

        Posture by ledger rule: ``unmitigated`` (nothing booked) ->
        ``under-mitigation`` (any non-terminal status) -> ``ineffective``
        (any implemented with effectiveness ``none``) -> ``mitigated``
        (all implemented, at least one ``full``, none ``none``) ->
        ``partially-mitigated`` (any ``partial``) -> ``abandoned`` (all
        abandoned). ``integrity_ok`` re-derives all in-scope digest pins as
        data. Seq is shape-validated only - never consumed, no audit row.
        """
        with self._lock:
            seq = self._check_read_seq(seq)
            hazard_id = _check_id(hazard_id, "hazard_id")
            if hazard_id not in self._hazard_mitigations:
                raise UnknownHazardError(f"unknown hazard: {hazard_id!r}")
            ids = self._hazard_mitigations[hazard_id]
            recs = [self._mitigations[i] for i in ids]
            statuses = [r.status for r in recs]
            implemented = [r for r in recs if r.status == "implemented"]
            n_implemented = len(implemented)
            n_full = sum(1 for r in implemented if r.effectiveness == "full")
            n_partial = sum(1 for r in implemented if r.effectiveness == "partial")
            n_none = sum(1 for r in implemented if r.effectiveness == "none")
            n_terminal = sum(1 for r in recs if r.status in TERMINAL_STATUSES)
            non_terminal = [s for s in statuses if s not in TERMINAL_STATUSES]
            if non_terminal:
                posture = "under-mitigation"
            elif n_none:
                posture = "ineffective"
            elif n_implemented and n_implemented == len(recs) and n_full:
                posture = "mitigated"
            elif n_partial:
                posture = "partially-mitigated"
            else:
                posture = "abandoned"
            integrity_ok = all(r.verify() for r in recs)
            provisional = EvaluationReport(
                hazard_id=hazard_id,
                seq=seq,
                posture=posture,
                n_mitigations=len(recs),
                n_implemented=n_implemented,
                n_full=n_full,
                n_partial=n_partial,
                n_none=n_none,
                n_terminal=n_terminal,
                integrity_ok=integrity_ok,
                digest="",
            )
            digest = _digest_pin(
                _evaluate_payload(provisional), "ai-compliance-mitigation.evaluate"
            )
            return EvaluationReport(
                hazard_id=hazard_id,
                seq=seq,
                posture=posture,
                n_mitigations=len(recs),
                n_implemented=n_implemented,
                n_full=n_full,
                n_partial=n_partial,
                n_none=n_none,
                n_terminal=n_terminal,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- views (pure reads, seq shape-validated only) ----------------------

    def mitigation_record(self, mitigation_id: str, seq: int) -> MitigationRecord:
        with self._lock:
            self._check_read_seq(seq)
            if mitigation_id not in self._mitigations:
                raise UnknownMitigationError(
                    f"unknown mitigation id: {mitigation_id!r}"
                )
            return self._mitigations[mitigation_id]

    def retire_record(self, hazard_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._check_read_seq(seq)
            if hazard_id not in self._retired:
                raise UnknownHazardError(f"unknown hazard: {hazard_id!r}")
            return self._retired[hazard_id]

    def mitigations_for(self, hazard_id: str, seq: int) -> Tuple[MitigationRecord, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(
                self._mitigations[i]
                for i in self._hazard_mitigations.get(hazard_id, [])
            )

    def hazard_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._hazard_mitigations))

    def mitigation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._mitigations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._check_read_seq(seq)
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._check_read_seq(seq)
            return {
                "n_hazards": len(self._hazard_mitigations),
                "n_mitigations": len(self._mitigations),
                "n_retired": len(self._retired),
                "seq": self._seq,
                "version": AI_COMPLIANCE_MITIGATION_VERSION,
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


def _drive_to_implemented(
    ledger: "AIComplianceMitigation",
    mitigation_id: str,
    seq: int,
    effectiveness: str = "full",
) -> Tuple["MitigationRecord", int]:
    """Test/self-check helper: drive one mitigation to implemented."""
    rec = ledger.update(mitigation_id, seq, "approved")
    rec = ledger.update(mitigation_id, seq + 1, "in-progress")
    rec = ledger.update(
        mitigation_id, seq + 2, "implemented", effectiveness=effectiveness
    )
    return rec, seq + 3


def main() -> None:
    """Self-check: exercise mitigate -> verify -> evaluate."""
    ledger = AIComplianceMitigation()
    assert stdlib_only(), "non-stdlib import detected"
    rec = ledger.mitigate("hazard-1", 1, strategy="compliance-assignment")
    assert rec.verify()
    _, nxt = _drive_to_implemented(ledger, rec.mitigation_id, 2)
    rep = ledger.verify(rec.mitigation_id, nxt)
    assert rep.verdict == "verified"
    ev = ledger.evaluate("hazard-1", nxt + 1)
    assert ev.posture == "mitigated"
    ret = ledger.retire("hazard-1", nxt + 2)
    assert ret.verify()
    print(
        "ai-compliance-mitigation OK: mitigate, update, verify, evaluate, "
        "retire, pins, audit"
    )


if __name__ == "__main__":
    main()
